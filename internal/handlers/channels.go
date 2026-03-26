package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// HandleChannelsStatus returns status of all configured channels (WhatsApp, Discord, etc.)
func (s *AppState) HandleChannelsStatus(w http.ResponseWriter, r *http.Request) {
	if !s.gw.Connected.Load() {
		json.NewEncoder(w).Encode(map[string]interface{}{"channels": []interface{}{}})
		return
	}

	// Call gateway channels.status
	raw, err := s.gw.Call("channels.status", map[string]interface{}{})
	if err != nil {
		log.Printf("[channels-status] error: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"channels": []interface{}{}, "error": err.Error()})
		return
	}

	// Parse response - OpenClaw format: {channels: {whatsapp: {...}, discord: {...}}}
	var fullResp struct {
		Channels map[string]interface{} `json:"channels"`
	}
	
	if json.Unmarshal(raw, &fullResp) == nil && len(fullResp.Channels) > 0 {
		var result []map[string]interface{}
		for id, data := range fullResp.Channels {
			if dataMap, ok := data.(map[string]interface{}); ok {
				dataMap["id"] = id
				if dataMap["name"] == nil {
					dataMap["name"] = id
				}
				result = append(result, dataMap)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"channels": result})
		return
	}

	// Fallback: empty array
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"channels": []interface{}{}})
}

// HandleWhatsAppQR returns QR code for WhatsApp pairing (or status if already connected)
func (s *AppState) HandleWhatsAppQR(w http.ResponseWriter, r *http.Request) {
	if !s.gw.Connected.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Gateway not connected"})
		return
	}

	// Determine action: "start" to trigger new QR, or just check status
	action := r.URL.Query().Get("action")
	if action == "" {
		action = "status"
	}

	var method string
	var params map[string]interface{}

	switch action {
	case "start":
		// Trigger new WhatsApp login flow
		method = "whatsapp_login"
		params = map[string]interface{}{
			"action": "start",
			"force":  true,
		}
	case "wait":
		// Wait for scan completion
		method = "whatsapp_login"
		params = map[string]interface{}{
			"action":    "wait",
			"timeoutMs": 60000,
		}
	default:
		// Just get current status (includes QR if available)
		method = "whatsapp_login"
		params = map[string]interface{}{
			"action": "start",
			"force":  false,
		}
	}

	raw, err := s.gw.Call(method, params)
	if err != nil {
		log.Printf("[whatsapp-qr] error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Forward response as-is
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// HandleChannelSessions returns active sessions for a specific channel
func (s *AppState) HandleChannelSessions(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		http.Error(w, "channel parameter required", http.StatusBadRequest)
		return
	}

	if !s.gw.Connected.Load() {
		json.NewEncoder(w).Encode(map[string]interface{}{"sessions": []interface{}{}})
		return
	}

	// Call sessions.list (no filter support, we'll filter clientside)
	raw, err := s.gw.Call("sessions.list", map[string]interface{}{
		"limit": 100,
	})
	if err != nil {
		log.Printf("[channel-sessions] error: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"sessions": []interface{}{}, "error": err.Error()})
		return
	}

	// Parse response - try wrapper or direct array
	var sessions []map[string]interface{}
	var wrapper map[string]interface{}
	if err := json.Unmarshal(raw, &wrapper); err == nil {
		if v, ok := wrapper["sessions"]; ok {
			if b, err := json.Marshal(v); err == nil {
				_ = json.Unmarshal(b, &sessions)
			}
		}
	}
	if sessions == nil {
		_ = json.Unmarshal(raw, &sessions)
	}

	// Filter sessions by channel - check nested fields
	var filtered []map[string]interface{}
	for _, s := range sessions {
		matched := false
		
		// Check origin.provider
		if origin, ok := s["origin"].(map[string]interface{}); ok {
			if provider, ok := origin["provider"].(string); ok && strings.EqualFold(provider, channel) {
				matched = true
			}
		}
		
		// Check deliveryContext.channel
		if !matched {
			if dc, ok := s["deliveryContext"].(map[string]interface{}); ok {
				if ch, ok := dc["channel"].(string); ok && strings.EqualFold(ch, channel) {
					matched = true
				}
			}
		}
		
		// Check lastChannel
		if !matched {
			if lastCh, ok := s["lastChannel"].(string); ok && strings.EqualFold(lastCh, channel) {
				matched = true
			}
		}
		
		if matched {
			filtered = append(filtered, s)
		}
	}

	log.Printf("[channel-sessions] channel=%s total=%d filtered=%d", channel, len(sessions), len(filtered))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"sessions": filtered})
}
