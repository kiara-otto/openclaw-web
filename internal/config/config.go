package config

import (
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
	GatewayToken   string `json:"gateway_token"`
	Username       string `json:"username"`
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
