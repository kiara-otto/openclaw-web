package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SessionInfo holds model and token info for the session.
type SessionInfo struct {
	Model         string `json:"model"`
	InputTokens   int64  `json:"inputTokens"`
	OutputTokens  int64  `json:"outputTokens"`
	TotalTokens   int64  `json:"totalTokens"`
	ContextTokens int64  `json:"contextTokens"`
}

// GetSessionInfo reads model and token info.
// Primary source: Gateway sessions.get RPC (live, authoritative).
// Fallback: local sessions.json file.
func (gc *Client) GetSessionInfo() SessionInfo {
	info := SessionInfo{}

	// Try Gateway RPC first (authoritative source via sessions.list)
	if gc.Connected.Load() {
		raw, err := gc.Call("sessions.list", map[string]interface{}{})
		if err == nil {
			// sessions.list returns an array of session objects
			var sessions []struct {
				Key              string `json:"key"`
				Model            string `json:"model"`
				ModelProvider    string `json:"modelProvider"`
				ModelOverride    string `json:"modelOverride"`
				ProviderOverride string `json:"providerOverride"`
				InputTokens      int64  `json:"inputTokens"`
				OutputTokens     int64  `json:"outputTokens"`
				TotalTokens      int64  `json:"totalTokens"`
				ContextTokens    int64  `json:"contextTokens"`
			}
			if json.Unmarshal(raw, &sessions) == nil {
				for _, sess := range sessions {
					if sess.Key != gc.sessionKey {
						continue
					}
					model := sess.ModelOverride
					provider := sess.ProviderOverride
					if model == "" {
						model = sess.Model
					}
					if provider == "" {
						provider = sess.ModelProvider
					}
					if model != "" {
						if provider != "" {
							info.Model = provider + "/" + model
						} else {
							info.Model = model
						}
					}
					info.InputTokens = sess.InputTokens
					info.OutputTokens = sess.OutputTokens
					info.TotalTokens = sess.TotalTokens
					info.ContextTokens = sess.ContextTokens
					if info.Model != "" {
						return info
					}
					break
				}
			}
		}
	}

	// Fallback: read from local sessions.json file
	info = gc.readSessionFromFile()
	if info.Model != "" {
		return info
	}

	// Third fallback: read default model from openclaw.json config
	cfgFile := filepath.Join(os.Getenv("HOME"), ".openclaw", "openclaw.json")
	cfgData, err := os.ReadFile(cfgFile)
	if err == nil {
		var oc struct {
			Agents struct {
				Defaults struct {
					Model json.RawMessage `json:"model"`
				} `json:"defaults"`
			} `json:"agents"`
		}
		if json.Unmarshal(cfgData, &oc) == nil && oc.Agents.Defaults.Model != nil {
			var modelStr string
			if json.Unmarshal(oc.Agents.Defaults.Model, &modelStr) == nil && modelStr != "" {
				info.Model = modelStr + " (default)"
				return info
			}
			var modelObj struct {
				Primary string `json:"primary"`
			}
			if json.Unmarshal(oc.Agents.Defaults.Model, &modelObj) == nil && modelObj.Primary != "" {
				info.Model = modelObj.Primary + " (default)"
				return info
			}
		}
	}

	if info.Model == "" {
		info.Model = "unknown"
	}
	return info
}

// readSessionFromFile reads session info from local sessions.json file
func (gc *Client) readSessionFromFile() SessionInfo {
	info := SessionInfo{}
	f := filepath.Join(os.Getenv("HOME"), ".openclaw", "agents", "main", "sessions", "sessions.json")
	data, err := os.ReadFile(f)
	if err != nil {
		return info
	}
	var sessions map[string]struct {
		Model            string `json:"model"`
		ModelProvider    string `json:"modelProvider"`
		ModelOverride    string `json:"modelOverride"`
		ProviderOverride string `json:"providerOverride"`
		InputTokens      int64  `json:"inputTokens"`
		OutputTokens     int64  `json:"outputTokens"`
		TotalTokens      int64  `json:"totalTokens"`
		ContextTokens    int64  `json:"contextTokens"`
	}
	if json.Unmarshal(data, &sessions) == nil {
		if s, ok := sessions[gc.sessionKey]; ok {
			model := s.ModelOverride
			provider := s.ProviderOverride
			if model == "" {
				model = s.Model
			}
			if provider == "" {
				provider = s.ModelProvider
			}
			if model != "" {
				if provider != "" {
					info.Model = provider + "/" + model
				} else {
					info.Model = model
				}
			}
			info.InputTokens = s.InputTokens
			info.OutputTokens = s.OutputTokens
			info.TotalTokens = s.TotalTokens
			info.ContextTokens = s.ContextTokens
		}
	}
	return info
}
