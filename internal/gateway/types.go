package gateway

import (
	"encoding/json"
)

// Gateway Request/Response Types

type Req struct {
	Type   string      `json:"type"`
	ID     string      `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

type Msg struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	OK      bool            `json:"ok,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Event   string          `json:"event,omitempty"`
}

type Error struct {
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }
