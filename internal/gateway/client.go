package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Client wraps the Gateway WebSocket connection
type Client struct {
	url        string
	token      string
	sessionKey string
	deviceId   string
	devicePub  string
	devicePriv []byte

	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]chan Msg

	Connected atomic.Bool

	// chat streaming state
	chatMu      sync.Mutex
	chatRunId   string // runId we're waiting for
	chatFinal   string
	chatStream  string
	chatDone    chan struct{}
}

// NewClient creates a new Gateway client
func NewClient(url, token, sessionKey, deviceId, devicePubKey, devicePrivKeyB64Url string) *Client {
	priv, _ := base64.RawURLEncoding.DecodeString(strings.TrimSpace(devicePrivKeyB64Url))
	return &Client{
		url:        url,
		token:      token,
		sessionKey: sessionKey,
		deviceId:   strings.TrimSpace(deviceId),
		devicePub:  strings.TrimSpace(devicePubKey),
		devicePriv: priv,
		pending:    make(map[string]chan Msg),
	}
}

// Start initiates the connection loop
func (gc *Client) Start() { go gc.loop() }

func (gc *Client) loop() {
	backoff := 800 * time.Millisecond
	for {
		if err := gc.run(); err != nil {
			log.Printf("[gw] error: %v — reconnect in %v", err, backoff)
		}
		gc.Connected.Store(false)
		time.Sleep(backoff)
		if backoff < 15*time.Second {
			backoff = time.Duration(float64(backoff) * 1.7)
		}
	}
}

func (gc *Client) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsURL := strings.Replace(strings.Replace(gc.url, "http://", "ws://", 1), "https://", "wss://", 1)

	// OpenClaw Gateway (newer versions) requires a valid Origin header for web-style clients.
	// Without it the gateway rejects the WS handshake with: "origin not allowed".
	origin := gc.url
	// Ensure origin uses http(s) (not ws(s))
	origin = strings.Replace(strings.Replace(origin, "ws://", "http://", 1), "wss://", "https://", 1)

	h := http.Header{}
	h.Set("Origin", origin)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		return err
	}
	conn.SetReadLimit(10 << 20)

	gc.mu.Lock()
	gc.conn = conn
	gc.mu.Unlock()

	// read-pump in background
	readErr := make(chan error, 1)
	go func() {
		for {
			var msg Msg
			if err := wsjson.Read(ctx, conn, &msg); err != nil {
				readErr <- err
				return
			}
			gc.dispatch(msg)
		}
	}()

	// give read-pump a moment
	time.Sleep(50 * time.Millisecond)

	// connect handshake
	signedAt := time.Now().UnixMilli()
	clientId := "gateway-client"
	// Use UI client mode (not webchat). Webchat clients are intentionally restricted
	// from session-admin methods like sessions.delete.
	clientMode := "ui"
	scopes := []string{"operator.admin", "operator.write", "operator.read"}
	payload := buildDeviceAuthPayload("v1", gc.deviceId, clientId, clientMode, "operator", scopes, signedAt, gc.token, "")
	sig := ""
	if len(gc.devicePriv) == ed25519.PrivateKeySize {
		sigBytes := ed25519.Sign(ed25519.PrivateKey(gc.devicePriv), []byte(payload))
		sig = base64.RawURLEncoding.EncodeToString(sigBytes)
	}

	_, err = gc.call(ctx, "connect", map[string]interface{}{
		"minProtocol": 3, "maxProtocol": 3,
		"client": map[string]string{"id": clientId, "version": "1.0.0", "platform": "go", "mode": clientMode},
		"device": map[string]interface{}{
			"id":        gc.deviceId,
			"publicKey":  gc.devicePub,
			"signature":  sig,
			"signedAt":   signedAt,
		},
		"role": "operator", "scopes": scopes,
		"auth": map[string]string{"token": gc.token},
	})
	if err != nil {
		conn.Close(websocket.StatusNormalClosure, "")
		return err
	}
	gc.Connected.Store(true)
	log.Printf("[gw] connected")

	return <-readErr
}

func buildDeviceAuthPayload(version, deviceId, clientId, clientMode, role string, scopes []string, signedAtMs int64, token, nonce string) string {
	// Must match OpenClaw buildDeviceAuthPayload():
	//   v1|deviceId|clientId|clientMode|role|scope1,scope2|signedAtMs|token
	// v2 adds |nonce at the end.
	sc := strings.Join(scopes, ",")
	if token == "" {
		token = ""
	}
	base := []string{
		version,
		deviceId,
		clientId,
		clientMode,
		role,
		sc,
		strconv.FormatInt(signedAtMs, 10),
		token,
	}
	if version == "v2" {
		base = append(base, nonce)
	}
	return strings.Join(base, "|")
}

func (gc *Client) dispatch(msg Msg) {
	switch msg.Type {
	case "res":
		gc.mu.Lock()
		ch, ok := gc.pending[msg.ID]
		if ok {
			delete(gc.pending, msg.ID)
		}
		gc.mu.Unlock()
		if ok {
			ch <- msg
		}
	case "event":
		if msg.Event == "chat" {
			gc.onChat(msg.Payload)
		} else if msg.Event == "agent" {
			gc.onAgent(msg.Payload)
		}
	}
}

func (gc *Client) onChat(raw json.RawMessage) {
	var ev struct {
		RunId      string `json:"runId"`
		SessionKey string `json:"sessionKey"`
		State      string `json:"state"`
	}
	json.Unmarshal(raw, &ev)
	if ev.SessionKey != gc.sessionKey {
		return
	}

	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()

	// Only process events for the run we're currently waiting on
	if gc.chatRunId != "" && ev.RunId != gc.chatRunId {
		log.Printf("[gw] chat event: state=%s runId=%s (ignoring, waiting for %s)", ev.State, ev.RunId, gc.chatRunId)
		return
	}

	log.Printf("[gw] chat event: state=%s runId=%s", ev.State, ev.RunId)

	switch ev.State {
	case "delta":
		text := extractText(raw)
		if text != "" {
			gc.chatStream = text
		}
	case "final":
		text := extractText(raw)
		if text == "" && gc.chatStream != "" {
			text = gc.chatStream
		}
		gc.chatFinal = text
		gc.chatStream = ""
		log.Printf("[gw] chat final text: %s", truncate(text, 200))
		if gc.chatDone != nil {
			close(gc.chatDone)
			gc.chatDone = nil
		}
	case "error", "aborted":
		gc.chatFinal = "[error]"
		gc.chatStream = ""
		if gc.chatDone != nil {
			close(gc.chatDone)
			gc.chatDone = nil
		}
	}
}

func (gc *Client) onAgent(raw json.RawMessage) {
	var ev struct {
		SessionKey string `json:"sessionKey"`
		Stream     string `json:"stream"`
		Data       struct {
			Text string `json:"text"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return
	}
	if ev.SessionKey != gc.sessionKey || ev.Stream != "assistant" {
		return
	}
	if ev.Data.Text == "" {
		return
	}

	gc.chatMu.Lock()
	gc.chatStream = ev.Data.Text // agent events send accumulated text
	gc.chatMu.Unlock()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func extractText(raw json.RawMessage) string {
	var ev struct{ Message json.RawMessage `json:"message"` }
	if json.Unmarshal(raw, &ev) != nil || ev.Message == nil {
		return ""
	}

	// Try as plain string
	var s string
	if json.Unmarshal(ev.Message, &s) == nil {
		return s
	}

	// Try as {role, content: [{type, text}], ...} (full message object)
	var fullMsg struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(ev.Message, &fullMsg) == nil && fullMsg.Content != nil {
		// content as string
		var cs string
		if json.Unmarshal(fullMsg.Content, &cs) == nil {
			return cs
		}
		// content as array of blocks
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(fullMsg.Content, &blocks) == nil {
			var parts []string
			for _, b := range blocks {
				if b.Type == "text" && b.Text != "" {
					parts = append(parts, b.Text)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "")
			}
		}
	}

	// Try as array of content blocks directly
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(ev.Message, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" {
				parts = append(parts, b.Text)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "")
		}
	}

	return string(ev.Message)
}

func (gc *Client) call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	id := randID()
	ch := make(chan Msg, 1)

	gc.mu.Lock()
	gc.pending[id] = ch
	c := gc.conn
	gc.mu.Unlock()

	if err := wsjson.Write(ctx, c, Req{Type: "req", ID: id, Method: method, Params: params}); err != nil {
		gc.mu.Lock()
		delete(gc.pending, id)
		gc.mu.Unlock()
		return nil, err
	}

	select {
	case r := <-ch:
		if !r.OK && r.Error != nil {
			return nil, r.Error
		}
		return r.Payload, nil
	case <-ctx.Done():
		gc.mu.Lock()
		delete(gc.pending, id)
		gc.mu.Unlock()
		return nil, ctx.Err()
	case <-time.After(120 * time.Second):
		gc.mu.Lock()
		delete(gc.pending, id)
		gc.mu.Unlock()
		return nil, &Error{"timeout"}
	}
}

// Call sends a WS-RPC request (external use)
func (gc *Client) Call(method string, params interface{}) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return gc.call(ctx, method, params)
}

// SessionKey returns the session key
func (gc *Client) SessionKey() string {
	return gc.sessionKey
}

// Chat streaming helper methods

// SetChatWait initializes chat wait state for a new message
func (gc *Client) SetChatWait(idempotencyKey string) {
	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()
	gc.chatRunId = idempotencyKey
	gc.chatFinal = ""
	gc.chatStream = ""
	gc.chatDone = make(chan struct{})
}

// ClearChatWait clears chat wait state
func (gc *Client) ClearChatWait() {
	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()
	gc.chatRunId = ""
}

// SetChatRunId sets the actual run ID (may differ from idempotency key)
func (gc *Client) SetChatRunId(runId string) {
	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()
	gc.chatRunId = runId
}

// GetChatRunId returns the current chat run ID
func (gc *Client) GetChatRunId() string {
	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()
	return gc.chatRunId
}

// GetChatText returns the accumulated chat text
func (gc *Client) GetChatText() string {
	gc.chatMu.Lock()
	defer gc.chatMu.Unlock()
	return gc.chatFinal
}

// WaitForChatDone waits for the chat to complete
func (gc *Client) WaitForChatDone(timeout time.Duration) bool {
	gc.chatMu.Lock()
	done := gc.chatDone
	gc.chatMu.Unlock()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// randID generates a random ID for requests
func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
