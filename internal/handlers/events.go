package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// EventHub is a tiny fan-out pubsub for SSE clients.
// We keep it intentionally simple: best-effort delivery, drop if a client is slow.
type EventHub struct {
	addCh  chan chan []byte
	delCh  chan chan []byte
	sendCh chan []byte
}

func NewEventHub() *EventHub {
	h := &EventHub{
		addCh:  make(chan chan []byte),
		delCh:  make(chan chan []byte),
		sendCh: make(chan []byte, 64),
	}
	go h.loop()
	return h
}

func (h *EventHub) loop() {
	clients := map[chan []byte]struct{}{}
	for {
		select {
		case ch := <-h.addCh:
			clients[ch] = struct{}{}
		case ch := <-h.delCh:
			if _, ok := clients[ch]; ok {
				delete(clients, ch)
				close(ch)
			}
		case msg := <-h.sendCh:
			for ch := range clients {
				select {
				case ch <- msg:
				default:
					// slow client -> drop message
				}
			}
		}
	}
}

func (h *EventHub) Add(ch chan []byte) { h.addCh <- ch }
func (h *EventHub) Del(ch chan []byte) { h.delCh <- ch }

func (h *EventHub) Broadcast(event string, data any) {
	b, _ := json.Marshal(data)
	// SSE framing
	payload := []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", event, string(b)))
	select {
	case h.sendCh <- payload:
	default:
		// hub congested; drop
	}
}

// HandleEvents streams Server-Sent Events.
func (s *AppState) HandleEvents(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan []byte, 16)
	s.hub.Add(ch)
	defer s.hub.Del(ch)

	// Initial snapshot
	sessionKey := r.URL.Query().Get("sessionKey")
	if sessionKey == "" {
		sessionKey = s.config.SessionKey
	}
	if ar, ok := s.getActiveRun(sessionKey); ok {
		s.hub.Broadcast("status", map[string]any{"sessionKey": sessionKey, "processing": true, "runId": ar.RunId})
	} else {
		s.hub.Broadcast("status", map[string]any{"sessionKey": sessionKey, "processing": false, "runId": ""})
	}
	s.hub.Broadcast("gateway", map[string]any{"connected": s.gw != nil && s.gw.Connected.Load()})

	// Heartbeat (prevents some proxies from buffering)
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	// Write loop
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			_, _ = w.Write(msg)
			fl.Flush()
		case <-ping.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			fl.Flush()
		}
	}
}
