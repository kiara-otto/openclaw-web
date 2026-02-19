package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"openclaw-web/internal/config"
	"openclaw-web/internal/gateway"
	"openclaw-web/internal/handlers"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	// Determine app name
	appName := filepath.Base(os.Args[0])
	if appName == "main" || appName == "server" {
		if cwd, err := os.Getwd(); err == nil {
			appName = filepath.Base(cwd)
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	gw := gateway.NewClient(cfg.GatewayURL, cfg.GatewayToken, cfg.SessionKey, cfg.DeviceID, cfg.DevicePublicKey, cfg.DevicePrivateKey)
	gw.Start()

	state := handlers.NewAppState(cfg, gw)

	if err := state.LoadModels(cfg.OpenClawConfig); err != nil {
		log.Printf("Warning: Could not load models: %v", err)
	}

	if _, err := state.LoadTemplates("templates"); err != nil {
		log.Printf("Warning: Could not load templates: %v, using fallback", err)
	}

	go state.CleanupSessions()
	go state.WatchModels()

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/api/login", state.HandleLogin)
	mux.HandleFunc("/api/logout", state.HandleLogout)
	mux.HandleFunc("/api/me", state.HandleMe)
	mux.HandleFunc("/api/models", state.HandleModels)
	mux.HandleFunc("/api/set-model", state.HandleSetModel)
	mux.HandleFunc("/api/chat", state.HandleChat)
	mux.HandleFunc("/api/gateway/restart", state.HandleGatewayRestart)
	mux.HandleFunc("/api/session/reset", state.HandleSessionReset)
	mux.HandleFunc("/api/history", state.HandleHistory)
	mux.HandleFunc("/api/message-log", state.HandleMessageLog)
	mux.HandleFunc("/api/change-password", state.HandleChangePassword)
	mux.HandleFunc("/api/vault", state.HandleVault)
	mux.HandleFunc("/api/sessions", state.HandleSessions)
	mux.HandleFunc("/api/session-delete", state.HandleSessionDelete)
	mux.HandleFunc("/api/session-info", state.HandleSessionInfo)
	mux.HandleFunc("/api/log", state.HandleLog)
	mux.HandleFunc("/", state.HandleIndex)

	handler := state.IPMiddleware(state.AuthMiddleware(mux))

	addr := ":" + cfg.Port
	appDisplayName := cfg.GetDisplayName()
	log.Printf("Starting %s on %s (allowed: %s)", appDisplayName, addr, cfg.IPRange)
	log.Printf("Gateway: %s | Session: %s", cfg.GatewayURL, cfg.SessionKey)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
