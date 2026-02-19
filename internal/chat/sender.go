package chat

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"

	"openclaw-web/internal/gateway"
)

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

// Sender handles chat message sending and streaming
type Sender struct {
	gw *gateway.Client
}

// NewSender creates a new chat sender
func NewSender(gw *gateway.Client) *Sender {
	return &Sender{gw: gw}
}

// Send sends a message and waits for the final response.
// Strategy:
//  1. Send chat.send, record the timestamp.
//  2. Wait for the chat "final" event (signals run complete).
//  3. If the final event or stream carried text, return it.
//  4. Otherwise poll chat.history to find the assistant's text answer.
//     The agent may produce text mixed with tool calls across multiple
//     steps, so we look for the LAST assistant message with a text block
//     whose timestamp >= sentAt. We poll with retries because the
//     "final" event may fire before the last message is persisted.
func (s *Sender) Send(message string) (string, error) {
	return s.SendToSession(message, s.gw.SessionKey())
}

// SendToSession sends a message to a specific session
func (s *Sender) SendToSession(message, sessionKey string) (string, error) {
	sentAt := time.Now().UnixMilli()
	idempotencyKey := randomID()

	s.gw.SetChatWait(idempotencyKey)
	defer s.gw.ClearChatWait()

	resp, err := s.gw.Call("chat.send", map[string]interface{}{
		"sessionKey":     sessionKey,
		"message":        message,
		"deliver":        false,
		"idempotencyKey": idempotencyKey,
	})
	if err != nil {
		return "", err
	}

	// Extract the runId from the response (may differ from idempotencyKey)
	var sendResp struct {
		RunId string `json:"runId"`
	}
	if json.Unmarshal(resp, &sendResp) == nil && sendResp.RunId != "" && sendResp.RunId != idempotencyKey {
		s.gw.SetChatRunId(sendResp.RunId)
	}
	log.Printf("[gw] chat.send runId=%s", s.gw.GetChatRunId())

	// Wait for the final signal (up to 120s)
	if !s.gw.WaitForChatDone(120 * time.Second) {
		return "", &gateway.Error{Message: "chat timeout"}
	}

	// Check if streaming/events gave us text
	r := s.gw.GetChatText()
	if r != "" {
		log.Printf("[gw] got text from events (%d chars)", len(r))
		return r, nil
	}

	// Poll chat.history
	log.Printf("[gw] no text from events, polling chat.history (sentAt=%d)", sentAt)
	for attempt := 1; attempt <= 8; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		text := s.fetchLastTextAfter(sessionKey, sentAt)
		if text != "" {
			log.Printf("[gw] history poll attempt %d: found text (%d chars)", attempt, len(text))
			return text, nil
		}
		log.Printf("[gw] history poll attempt %d: no text yet", attempt)
	}

	log.Printf("[gw] history poll exhausted, returning empty")
	return "", nil
}

// fetchLastTextAfter fetches chat history and returns the text of the last
// assistant message (with a text block) whose timestamp >= sentAt.
func (s *Sender) fetchLastTextAfter(sessionKey string, sentAt int64) string {
	raw, err := s.gw.Call("chat.history", map[string]interface{}{
		"sessionKey": sessionKey,
		"limit":      50,
	})
	if err != nil {
		log.Printf("[history] error: %v", err)
		return ""
	}

	var hist struct {
		Messages []struct {
			Role       string          `json:"role"`
			Content    json.RawMessage `json:"content"`
			Timestamp  int64           `json:"timestamp"`
			StopReason string          `json:"stopReason"`
		} `json:"messages"`
	}
	if json.Unmarshal(raw, &hist) != nil {
		return ""
	}

	// Walk backwards: find the last assistant message with text, after sentAt.
	var fallbackText string
	for i := len(hist.Messages) - 1; i >= 0; i-- {
		m := hist.Messages[i]
		if m.Role != "assistant" {
			continue
		}
		if m.Timestamp > 0 && m.Timestamp < sentAt {
			break
		}
		text := extractContent(m.Content)
		if text == "" {
			continue
		}
		if m.StopReason == "stop" || m.StopReason == "end_turn" || m.StopReason == "max_tokens" {
			return text
		}
		if fallbackText == "" {
			fallbackText = text
		}
	}

	return fallbackText
}

// extractContent extracts text from a content field (string or [{type,text}]).
func extractContent(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return stripModelTags(s)
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
		return stripModelTags(strings.Join(parts, ""))
	}
	return stripModelTags(string(raw))
}

// stripModelTags removes wrapper tags some models add
func stripModelTags(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<final>") && strings.HasSuffix(s, "</final>") {
		s = strings.TrimPrefix(s, "<final>")
		s = strings.TrimSuffix(s, "</final>")
		s = strings.TrimSpace(s)
	}
	return s
}
