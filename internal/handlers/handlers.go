package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"openclaw-web/internal/auth"
	"openclaw-web/internal/config"
	"openclaw-web/internal/gateway"
)

// Session represents a web session
type Session struct {
	ID        string
	Username  string
	ExpiresAt time.Time
}

// ModelInfo represents a model
type ModelInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// AppState holds the application state
type AppState struct {
	config    *config.Config
	gw        *gateway.Client
	sessions  map[string]*Session
	sessionMu sync.RWMutex

	models        []ModelInfo
	modelsMu      sync.RWMutex
	modelsModTime time.Time
	modelsSource  string // "gateway" | "config"

	templates *template.Template
}

// NewAppState creates a new app state
func NewAppState(cfg *config.Config, gw *gateway.Client) *AppState {
	return &AppState{
		config:    cfg,
		gw:        gw,
		sessions:  make(map[string]*Session),
		templates: template.New("templates"),
	}
}

// LoadTemplates loads HTML templates
func (s *AppState) LoadTemplates(dir string) (*template.Template, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return s.templates, nil
	}
	templates, err := template.ParseGlob(filepath.Join(dir, "*.html"))
	if err != nil {
		return nil, err
	}
	s.templates = templates
	return templates, nil
}

// GetTemplates returns the templates
func (s *AppState) GetTemplates() *template.Template {
	return s.templates
}

// ===== Model Loading =====

func loadModelsViaOpenClawCLI(configPath string) ([]ModelInfo, error) {
	// `openclaw models list --json` returns { count, models: [{ key, name, ... }] }
	cmd := exec.Command("openclaw", "models", "list", "--json")
	// Ensure we use the same config file as the webapp.
	cmd.Env = append(os.Environ(), "OPENCLAW_CONFIG_PATH="+configPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var resp struct {
		Models []struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}

	models := make([]ModelInfo, 0, len(resp.Models))
	for _, m := range resp.Models {
		key := strings.TrimSpace(m.Key)
		if key == "" {
			continue
		}
		provider := ""
		id := key
		if i := strings.Index(key, "/"); i >= 0 {
			provider = key[:i]
			id = key[i+1:]
		}
		models = append(models, ModelInfo{ID: id, Name: m.Name, Provider: provider})
	}
	return models, nil
}


// LoadModels loads models.
//
// Important: OpenClaw supports `models.mode = "merge"`, which means the *effective*
// allowlist is the merge of built-in defaults + the config additions/overrides.
// When in merge mode and the Gateway is connected, we prefer the Gateway’s
// resolved catalog (`models.list`) so the UI shows *all* allowed models.
func (s *AppState) LoadModels(configPath string) error {
	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg struct {
		Models struct {
			Mode      string `json:"mode"`
			Providers map[string]struct {
				Models []ModelInfo `json:"models"`
			} `json:"providers"`
		} `json:"models"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	// If we’re in merge mode, the config file alone is not the full picture.
	// The most accurate "allowed" list is what `openclaw models list` prints
	// (same as the TUI /models), because it resolves defaults+aliases+fallbacks.
	if strings.EqualFold(strings.TrimSpace(cfg.Models.Mode), "merge") {
		// Try CLI first (matches TUI), then fall back to config parsing.
		if merged, err := loadModelsViaOpenClawCLI(configPath); err == nil {
			s.modelsMu.Lock()
			s.models = merged
			s.modelsModTime = info.ModTime()
			s.modelsSource = "openclaw-cli"
			s.modelsMu.Unlock()
			log.Printf("[models] loaded %d models via openclaw CLI (merge mode)", len(merged))
			return nil
		}

		// Fallback: If CLI fails but Gateway is up, you *can* still fetch the gateway catalog,
		// but it may include many non-allowed models. We intentionally do NOT use it here.
		log.Printf("[models] openclaw CLI model listing failed (merge mode), falling back to config parsing")
	}

	// Config-only parsing (works for mode="replace" or when gateway isn’t available).
	var models []ModelInfo
	for provider, p := range cfg.Models.Providers {
		for _, m := range p.Models {
			m.Provider = provider
			models = append(models, m)
		}
	}

	s.modelsMu.Lock()
	s.models = models
	s.modelsModTime = info.ModTime()
	s.modelsSource = "config"
	s.modelsMu.Unlock()
	log.Printf("[models] loaded %d models from config", len(models))
	return nil
}

// RefreshModelsIfNeeded checks if config was modified
func (s *AppState) RefreshModelsIfNeeded() {
	configPath := s.config.OpenClawConfig
	info, err := os.Stat(configPath)
	if err != nil {
		return
	}

	s.modelsMu.RLock()
	lastMod := s.modelsModTime
	src := s.modelsSource
	s.modelsMu.RUnlock()

	// Normal path: reload when config changes.
	if info.ModTime().After(lastMod) {
		if err := s.LoadModels(configPath); err != nil {
			log.Printf("[models] refresh error: %v", err)
		}
		return
	}

	// Special case: in merge mode we may have started while the Gateway was still
	// connecting, so the first load fell back to config-only. When the Gateway
	// becomes available later, refresh once even without a config modtime change.
	if src != "gateway" && s.gw != nil && s.gw.Connected.Load() {
		if err := s.LoadModels(configPath); err != nil {
			log.Printf("[models] refresh (gateway available) error: %v", err)
		}
	}
}

// WatchModels periodically checks for config changes
func (s *AppState) WatchModels() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.RefreshModelsIfNeeded()
	}
}

// ===== Session Cleanup =====

// CleanupSessions removes expired sessions
func (s *AppState) CleanupSessions() {
	for range time.NewTicker(5 * time.Minute).C {
		s.sessionMu.Lock()
		now := time.Now()
		for id, sess := range s.sessions {
			if now.After(sess.ExpiresAt) {
				delete(s.sessions, id)
			}
		}
		s.sessionMu.Unlock()
	}
}

// ===== Handlers =====

// HandleMe returns current user info
func (s *AppState) HandleMe(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	s.modelsMu.RLock()
	models := s.models
	s.modelsMu.RUnlock()
	info := s.gw.GetSessionInfo()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":      username,
		"currentModel":  info.Model,
		"inputTokens":   info.InputTokens,
		"outputTokens":  info.OutputTokens,
		"totalTokens":   info.TotalTokens,
		"contextTokens": info.ContextTokens,
		"models":        models,
		"connected":     s.gw.Connected.Load(),
		"sessionKey":    s.config.SessionKey,
	})
}

// HandleModels returns available models
func (s *AppState) HandleModels(w http.ResponseWriter, r *http.Request) {
	s.modelsMu.RLock()
	defer s.modelsMu.RUnlock()
	json.NewEncoder(w).Encode(s.models)
}

// HandleSetModel sets the current model
func (s *AppState) HandleSetModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	modelID := r.FormValue("model")
	if modelID == "" {
		http.Error(w, "Model ID required", http.StatusBadRequest)
		return
	}
	if !s.gw.Connected.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	raw, err := s.gw.Call("sessions.patch", map[string]interface{}{
		"key":   s.config.SessionKey,
		"model": modelID,
	})
	if err != nil {
		log.Printf("[set-model] sessions.patch error for model=%s: %v", modelID, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("[set-model] model set to %s (response: %s)", modelID, truncate(string(raw), 200))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "model": modelID})
}

// HandleChat handles chat messages
func (s *AppState) HandleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Message    string `json:"message"`
		SessionKey string `json:"sessionKey,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !s.gw.Connected.Load() {
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	sentAt := time.Now().UnixMilli()

	var resp string
	var err error
	if req.SessionKey != "" && req.SessionKey != s.config.SessionKey {
		// Send to foreign session
		idempotencyKey := auth.RandomID()
		raw, callErr := s.gw.Call("chat.send", map[string]interface{}{
			"sessionKey":     req.SessionKey,
			"message":        req.Message,
			"deliver":        true,
			"idempotencyKey": idempotencyKey,
		})
		if callErr != nil {
			err = callErr
		} else {
			var sendResp struct {
				RunId string `json:"runId"`
			}
			if json.Unmarshal(raw, &sendResp) == nil && sendResp.RunId != "" {
				resp = "[sent to " + req.SessionKey + "]"
			} else {
				resp = "[sent]"
			}
		}
	} else {
		// Default session
		resp, err = s.sendChat(req.Message)
	}

	receivedAt := time.Now().UnixMilli()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"text":        resp,
		"sentAt":      sentAt,
		"receivedAt":  receivedAt,
	})
}

// sendChat sends a message and waits for response (simplified version)
func (s *AppState) sendChat(message string) (string, error) {
	idempotencyKey := auth.RandomID()

	s.gw.SetChatWait(idempotencyKey)
	defer s.gw.ClearChatWait()

	resp, err := s.gw.Call("chat.send", map[string]interface{}{
		"sessionKey":     s.config.SessionKey,
		"message":        message,
		"deliver":        false,
		"idempotencyKey": idempotencyKey,
	})
	if err != nil {
		return "", err
	}

	var sendResp struct {
		RunId string `json:"runId"`
	}
	if json.Unmarshal(resp, &sendResp) == nil && sendResp.RunId != "" {
		s.gw.SetChatRunId(sendResp.RunId)
	}

	if !s.gw.WaitForChatDone(120 * time.Second) {
		return "", &gateway.Error{Message: "chat timeout"}
	}

	return s.gw.GetChatText(), nil
}

// HandleHistory returns chat history
func (s *AppState) HandleHistory(w http.ResponseWriter, r *http.Request) {
	if !s.gw.Connected.Load() {
		json.NewEncoder(w).Encode(map[string]interface{}{"messages": []interface{}{}})
		return
	}

	sessionKey := r.URL.Query().Get("session")
	if sessionKey == "" {
		sessionKey = s.config.SessionKey
	}

	raw, err := s.gw.Call("chat.history", map[string]interface{}{
		"sessionKey": sessionKey,
		"limit":      50,
	})
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"messages": []interface{}{}, "error": err.Error()})
		return
	}

	type rawMsg struct {
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		Timestamp interface{}     `json:"timestamp"`
	}
	var hist struct {
		Messages []rawMsg `json:"messages"`
	}
	if err := json.Unmarshal(raw, &hist); err != nil {
		var msgs []rawMsg
		if err2 := json.Unmarshal(raw, &msgs); err2 != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"messages": []interface{}{}, "error": "parse error"})
			return
		}
		hist.Messages = msgs
	}

	type outMsg struct {
		Role      string          `json:"role"`
		Text      string          `json:"text"`
		Timestamp interface{}     `json:"timestamp,omitempty"`
		Raw       json.RawMessage `json:"raw,omitempty"`
	}
	var out []outMsg
	for _, m := range hist.Messages {
		if m.Role != "user" && m.Role != "assistant" {
			continue
		}
		text := s.extractContent(m.Content)
		if text == "" {
			continue
		}
		rawDebug, _ := json.Marshal(m)
		out = append(out, outMsg{
			Role:      m.Role,
			Text:      text,
			Timestamp: m.Timestamp,
			Raw:       rawDebug,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"messages": out})
}

// extractContent extracts text from content field
func (s *AppState) extractContent(raw json.RawMessage) string {
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return s.stripUserTimestampPrefix(s.stripOpenClawMeta(s.stripModelTags(str)))
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return s.stripUserTimestampPrefix(s.stripOpenClawMeta(s.stripModelTags(strings.Join(parts, ""))))
	}
	return s.stripUserTimestampPrefix(s.stripOpenClawMeta(s.stripModelTags(string(raw))))
}

func (s *AppState) stripModelTags(str string) string {
	str = strings.TrimSpace(str)
	if strings.HasPrefix(str, "<final>") && strings.HasSuffix(str, "</final>") {
		str = strings.TrimPrefix(str, "<final>")
		str = strings.TrimSuffix(str, "</final>")
		str = strings.TrimSpace(str)
	}
	return str
}

var userTimestampPrefixRe = regexp.MustCompile(`^\[[A-Za-z]{3}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+GMT[+-]\d+\]\s+`)

func (s *AppState) stripUserTimestampPrefix(str string) string {
	str = strings.TrimSpace(str)
	return strings.TrimSpace(userTimestampPrefixRe.ReplaceAllString(str, ""))
}

// stripOpenClawMeta removes gateway/UI debug envelopes that sometimes end up in transcripts.
func (s *AppState) stripOpenClawMeta(str string) string {
	str = strings.TrimSpace(str)
	if str == "" {
		return str
	}

	lines := strings.Split(str, "\n")
	out := make([]string, 0, len(lines))
	inMetaBlock := false
	inCodeFence := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)

		// Drop leading "System:" noise lines.
		if len(out) == 0 && strings.HasPrefix(trim, "System:") {
			continue
		}

		// Remove the "Conversation info (untrusted metadata):```json ...```" block.
		if strings.HasPrefix(trim, "Conversation info (untrusted metadata):") {
			inMetaBlock = true
			inCodeFence = false
			continue
		}
		if inMetaBlock {
			if strings.HasPrefix(trim, "```") {
				// toggle fence
				inCodeFence = !inCodeFence
				// if we just closed the fence, end meta block
				if !inCodeFence {
					inMetaBlock = false
				}
			}
			continue
		}

		out = append(out, line)
	}

	res := strings.TrimSpace(strings.Join(out, "\n"))
	return res
}

// HandleMessageLog returns raw JSONL transcript
func (s *AppState) HandleMessageLog(w http.ResponseWriter, r *http.Request) {
	sessionsFile := os.ExpandEnv("$HOME/.openclaw/agents/main/sessions/sessions.json")
	sdata, err := os.ReadFile(sessionsFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "sessions file not readable"})
		return
	}
	var sessions map[string]struct{ SessionFile string `json:"sessionFile"` }
	if err := json.Unmarshal(sdata, &sessions); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "sessions.json parse error"})
		return
	}
	entry, ok := sessions[s.config.SessionKey]
	if !ok || entry.SessionFile == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"lines": []string{}})
		return
	}
	b, err := os.ReadFile(entry.SessionFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "session transcript unreadable"})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	json.NewEncoder(w).Encode(map[string]interface{}{"lines": lines})
}

// HandleChangePassword changes the password
func (s *AppState) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}
	if req.Current == "" || req.New == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "both fields required"})
		return
	}
	if len(req.New) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "password too short (min 4)"})
		return
	}

	if !auth.VerifyPassword(req.Current, s.config.PasswordHash) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "current password incorrect"})
		return
	}

	newHash := auth.HashPassword(req.New)
	s.config.UpdatePassword(newHash)
	
	if err := s.config.Save("config.json"); err != nil {
		log.Printf("[pw] failed to write config: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": "saved in memory but failed to write config file"})
		return
	}

	log.Printf("[pw] password changed successfully")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleGatewayRestart restarts the Gateway
func (s *AppState) HandleGatewayRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cmd := exec.Command("/opt/homebrew/bin/openclaw", "gateway", "restart")
	output, err := cmd.CombinedOutput()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "output": string(output)})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": string(output)})
}

// HandleSessionReset resets the session
func (s *AppState) HandleSessionReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.gw.Connected.Load() {
		// sessions.delete requires operator.admin in newer OpenClaw versions.
		// sessions.reset achieves the same UX (fresh session) with lower privileges.
		_, err := s.gw.Call("sessions.reset", map[string]interface{}{
			"key":    s.config.SessionKey,
			"reason": "reset",
		})
		if err != nil {
			log.Printf("[session-reset] error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[session-reset] session %s reset", s.config.SessionKey)
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleSessions returns list of sessions
func (s *AppState) HandleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.gw.Connected.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	raw, err := s.gw.Call("sessions.list", map[string]interface{}{})
	if err != nil {
		log.Printf("[sessions] error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Write(raw)
}

// HandleSessionDelete deletes a session
func (s *AppState) HandleSessionDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "session key required"})
		return
	}

	if req.Key == s.config.SessionKey {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "cannot delete own session"})
		return
	}

	if !s.gw.Connected.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	_, err := s.gw.Call("sessions.delete", map[string]interface{}{"key": req.Key})
	if err != nil {
		log.Printf("[session-delete] error for key=%s: %v", req.Key, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	log.Printf("[session-delete] deleted session: %s", req.Key)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "key": req.Key})
}

// HandleSessionInfo returns session info
func (s *AppState) HandleSessionInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionKey := r.URL.Query().Get("session")
	if sessionKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "session parameter required"})
		return
	}

	if !s.gw.Connected.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	raw, err := s.gw.Call("sessions.list", map[string]interface{}{})
	if err != nil {
		log.Printf("[session-info] error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var sessions []struct {
		Key           string `json:"key"`
		Model         string `json:"model"`
		TotalTokens   int64  `json:"totalTokens"`
		ContextTokens int64  `json:"contextTokens"`
	}
	if err := json.Unmarshal(raw, &sessions); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "parse error"})
		return
	}

	for _, sess := range sessions {
		if sess.Key == sessionKey {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"model":         sess.Model,
				"totalTokens":   sess.TotalTokens,
				"contextTokens": sess.ContextTokens,
			})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "session not found"})
}

// HandleVault handles vault lock/unlock
func (s *AppState) HandleVault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vaultHome := os.ExpandEnv("$HOME/.openclaw/vault")
	stateFile := filepath.Join(vaultHome, "run", "state.json")
	mountPath := filepath.Join(vaultHome, "run", "mnt")
	imagePath := filepath.Join(vaultHome, "store", "vault.dmg.sparsebundle")

	isUnlocked := func() bool {
		if _, err := os.Stat(stateFile); err != nil {
			return false
		}
		if _, err := os.Stat(mountPath); err != nil {
			return false
		}
		out, err := exec.Command("/sbin/mount").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), mountPath)
	}

	if r.Method == http.MethodGet {
		unlocked := isUnlocked()
		resp := map[string]interface{}{
			"status": "locked",
		}
		if unlocked {
			resp["status"] = "unlocked"
			resp["mount"] = mountPath
			if data, err := os.ReadFile(stateFile); err == nil {
				var state map[string]interface{}
				if json.Unmarshal(data, &state) == nil {
					if ua, ok := state["unlockedAt"]; ok {
						resp["unlockedAt"] = ua
					}
				}
			}
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action     string `json:"action"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}

	switch req.Action {
	case "lock":
		if !isUnlocked() {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "already locked"})
			return
		}
		cmd := exec.Command("hdiutil", "detach", mountPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[vault] lock error: %v — %s", err, string(out))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "lock failed: " + strings.TrimSpace(string(out))})
			return
		}
		os.Remove(stateFile)
		log.Printf("[vault] locked successfully")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "locked"})

	case "unlock":
		if isUnlocked() {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "already unlocked"})
			return
		}
		if req.Passphrase == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "passphrase required"})
			return
		}

		os.MkdirAll(mountPath, 0700)
		os.MkdirAll(filepath.Dir(stateFile), 0700)

		cmd := exec.Command("hdiutil", "attach",
			"-nobrowse",
			"-mountpoint", mountPath,
			"-owners", "on",
			"-stdinpass",
			imagePath,
		)
		cmd.Stdin = strings.NewReader(req.Passphrase)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[vault] unlock error: %v — %s", err, string(out))
			errMsg := strings.TrimSpace(string(out))
			if strings.Contains(errMsg, "Authentication error") || strings.Contains(errMsg, "passphrase") {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "wrong passphrase"})
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "unlock failed: " + errMsg})
			}
			return
		}

		state := map[string]string{
			"backend":    "macos-hdiutil",
			"vaultHome":  vaultHome,
			"mount":      mountPath,
			"unlockedAt": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}
		stateData, _ := json.MarshalIndent(state, "", "  ")
		os.WriteFile(stateFile, stateData, 0600)

		log.Printf("[vault] unlocked successfully")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "unlocked"})

	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown action (use 'lock' or 'unlock')"})
	}
}

// HandleLog handles log file viewing
func (s *AppState) HandleLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	action := r.URL.Query().Get("action")

	logDir := os.ExpandEnv("$HOME/.openclaw/logs")
	appName := s.config.ExtractAppName()
	appLogName := appName + ".log"

	// Determine app log path: binary dir if valid, else cwd
	appLogPath := ""
	if len(os.Args) > 0 && os.Args[0] != "" && os.Args[0] != "main" && !strings.HasPrefix(os.Args[0], "/var/") && !strings.HasPrefix(os.Args[0], "/tmp/") {
		binDir := filepath.Dir(os.Args[0])
		if binDir != "" && binDir != "." {
			appLogPath = filepath.Join(binDir, appLogName)
		}
	}
	if appLogPath == "" {
		if cwd, err := os.Getwd(); err == nil {
			appLogPath = filepath.Join(cwd, appLogName)
		}
	}

	if action == "list" || r.URL.Query().Get("file") == "" {
		type logFile struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			Path string `json:"-"`
		}
		var files []logFile

		if info, err := os.Stat(appLogPath); err == nil {
			files = append(files, logFile{Name: appLogName, Size: info.Size(), Path: appLogPath})
		}

		filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(path, ".log") {
				name := filepath.Base(path)
				files = append(files, logFile{Name: name, Size: info.Size(), Path: path})
			}
			return nil
		})

		json.NewEncoder(w).Encode(map[string]interface{}{"files": files})
		return
	}

	fileName := r.URL.Query().Get("file")
	fileName = filepath.Base(fileName)
	if !strings.HasSuffix(fileName, ".log") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid file name"})
		return
	}

	var filePath string
	if fileName == appLogName {
		filePath = appLogPath
	} else {
		filePath = filepath.Join(logDir, fileName)
	}

	if _, err := os.Stat(filePath); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "file not found"})
		return
	}

	linesParam := r.URL.Query().Get("lines")
	numLines := 50
	if linesParam != "" {
		if n, err := parseInt(linesParam); err == nil && n > 0 && n <= 500 {
			numLines = n
		}
	}

	beforeParam := r.URL.Query().Get("before")
	beforeLine := -1
	if beforeParam != "" {
		if n, err := parseInt(beforeParam); err == nil && n >= 0 {
			beforeLine = n
		}
	}

	lines, totalLines, err := tailFile(filePath, numLines, beforeLine)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	firstLine := 0
	if beforeLine < 0 {
		firstLine = totalLines - len(lines)
	} else {
		firstLine = beforeLine - len(lines)
	}
	if firstLine < 0 {
		firstLine = 0
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"file":       fileName,
		"lines":      lines,
		"totalLines": totalLines,
		"firstLine":  firstLine,
		"hasMore":    firstLine > 0,
	})
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &gateway.Error{Message: "not a number"}
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func tailFile(path string, count int, beforeLine int) ([]string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		return []string{}, 0, nil
	}

	allLines := strings.Split(content, "\n")
	total := len(allLines)

	end := total
	if beforeLine >= 0 && beforeLine < total {
		end = beforeLine
	}

	start := end - count
	if start < 0 {
		start = 0
	}

	return allLines[start:end], total, nil
}

// HandleLogin handles login
func (s *AppState) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.templates.ExecuteTemplate(w, "login.html", map[string]string{"DisplayName": s.config.GetDisplayName()})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	// Check credentials
	if username != s.config.Username || !auth.VerifyPassword(password, s.config.PasswordHash) {
		s.templates.ExecuteTemplate(w, "login.html", map[string]string{"DisplayName": s.config.GetDisplayName(), "Error": "Invalid credentials"})
		return
	}
	
	sessionID := auth.RandomID()
	s.sessionMu.Lock()
	s.sessions[sessionID] = &Session{ID: sessionID, Username: username, ExpiresAt: time.Now().Add(24 * time.Hour)}
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionID, Path: "/", Expires: time.Now().Add(24 * time.Hour), HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogout handles logout
func (s *AppState) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		s.sessionMu.Lock()
		delete(s.sessions, c.Value)
		s.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// HandleIndex handles the main page
func (s *AppState) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Username") == "" {
		s.templates.ExecuteTemplate(w, "login.html", map[string]interface{}{"DisplayName": s.config.GetDisplayName()})
		return
	}
	s.templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"DisplayName":  s.config.GetDisplayName(),
		"VaultEnabled": s.config.IsVaultEnabled(),
	})
}

// ===== Middleware =====

// IPMiddleware restricts access by IP
func (s *AppState) IPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipStr := strings.Split(r.RemoteAddr, ":")[0]
		ip := net.ParseIP(ipStr)
		_, network, _ := net.ParseCIDR(s.config.IPRange)
		if network != nil && !network.Contains(ip) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware handles authentication
func (s *AppState) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		isPageRoot := r.URL.Path == "/" || r.URL.Path == "/login"

		cookie, err := r.Cookie("session")
		authed := false
		if err == nil {
			s.sessionMu.RLock()
			sess, ok := s.sessions[cookie.Value]
			s.sessionMu.RUnlock()
			if ok && time.Now().Before(sess.ExpiresAt) {
				authed = true
				r.Header.Set("X-Username", sess.Username)
			}
		}

		if authed {
			next.ServeHTTP(w, r)
			return
		}

		if isPageRoot {
			next.ServeHTTP(w, r)
			return
		}
		if isAPI {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// ===== Helpers =====

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
