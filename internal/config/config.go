package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	"openclaw-web/internal/auth"
)

type Config struct {
	Port           string `json:"port"`
	IPRange        string `json:"ip_range"`
	GatewayURL     string `json:"gateway_url"`
	GatewayToken      string `json:"gateway_token"`
	DeviceID          string `json:"device_id"`
	DevicePublicKey   string `json:"device_public_key"`
	DevicePrivateKey  string `json:"device_private_key"`
	Username          string `json:"username"`
	PasswordHash   string `json:"password_hash"`
	OpenClawConfig string `json:"openclaw_config"`
	SessionKey     string `json:"session_key"`
	DisplayName    string `json:"display_name"`
	VaultEnabled   *bool  `json:"vault_enabled,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return &Config{
			Port: "8080", IPRange: "10.9.9.0/24",
			GatewayURL: "http://localhost:18789",
			Username: "admin", PasswordHash: auth.HashPassword("admin"),
			OpenClawConfig: "$HOME/.openclaw/openclaw.json",
			SessionKey: "agent:main:<Name>",
		}, nil
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.SessionKey == "" {
		cfg.SessionKey = "agent:main"
	}
	changed := false

	// Ensure a stable device keypair for Gateway device identity.
	// OpenClaw expects base64url (no padding) strings.
	if strings.TrimSpace(cfg.DevicePublicKey) == "" || strings.TrimSpace(cfg.DevicePrivateKey) == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.DevicePublicKey = base64.RawURLEncoding.EncodeToString(pub)
		cfg.DevicePrivateKey = base64.RawURLEncoding.EncodeToString(priv)
		log.Printf("[config] generated device keypair (pub=%s...)", cfg.DevicePublicKey[:8])
		changed = true
	}

	// DeviceID must match OpenClaw's deriveDeviceIdFromPublicKey(): sha256(raw_pubkey_bytes).hex
	pubRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cfg.DevicePublicKey))
	if err == nil && len(pubRaw) > 0 {
		d := sha256.Sum256(pubRaw)
		derived := hex.EncodeToString(d[:])
		if strings.TrimSpace(cfg.DeviceID) != derived {
			cfg.DeviceID = derived
			log.Printf("[config] set device_id from public key (device_id=%s...)", cfg.DeviceID[:8])
			changed = true
		}
	}

	if changed {
		// best-effort persist
		_ = cfg.Save(path)
	}
	return &cfg, nil
}

func (c *Config) ExtractAppName() string {
	// Use current directory name as primary source (works for both `go run` and compiled binaries)
	if cwd, err := os.Getwd(); err == nil {
		dirName := filepath.Base(cwd)
		if dirName != "" && dirName != "/" {
			return dirName
		}
	}
	// Fallback: extract from session key
	parts := strings.Split(c.SessionKey, ":")
	return parts[len(parts)-1]
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (c *Config) GetDisplayName() string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return strings.Title(c.ExtractAppName())
}

func (c *Config) IsVaultEnabled() bool {
	if c.VaultEnabled == nil {
		return true // default: enabled
	}
	return *c.VaultEnabled
}

func (c *Config) UpdatePassword(newHash string) {
	c.PasswordHash = newHash
	log.Printf("[config] password updated")
}
