# GATEWAY-SETUP.md — OpenClaw Web + Gateway Integration

Diese Anleitung erklärt, wie du OpenClaw Web mit deinem OpenClaw Gateway verbindest.

## Voraussetzungen

- OpenClaw Gateway läuft (mind. v2026.2.0).
- Vault ist **geöffnet** (wird bei Session-Start geprüft).
- Go 1.25.6+ installiert.

## Schritt 1: Gateway-Token extrahieren

Das Token findest du in deiner OpenClaw-Config:

```bash
# Vollständige Config anzeigen
cat ~/.openclaw/openclaw.json | grep -A10 '"gateway"'

# Nur Token extrahieren
jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json
```

Kopiere den Token-Wert (lange hex-Zeichenkette) in `config.json` unter `gateway_token`.

## Schritt 2: Gateway-URL ermitteln

Standard-URL: `http://localhost:18789` (wenn Gateway und Web auf **gleichem Gerät** laufen).

Falls Gateway auf anderem Host:

```bash
# Config prüfen
jq -r '.gateway.url // "http://localhost:18789"' ~/.openclaw/openclaw.json
```

- **Raspberry Pi / Server-Setup:** Gateway auf Pi (`http://<pi-ip>:18789`), Web auf Laptop (`http://127.0.0.1:18789` → funktioniert nicht!). In `config.json` dann: `gateway_url: "http://<pi-ip>:18789"`.
- **Laptop-Setup:** Beide lokal → `http://localhost:18789`.

## Schritt 3: Device Keys generieren (falls erforderlich)

Die Web-App authentifiziert sich als **Operator-Client** mit dem Gateway-Token. **Kein Pairing nötig!**

**Falls Device Keys in config.json erforderlich (z.B. für erweiterte Features):**

### Device ID + Keys erzeugen

```bash
# Neues Device-Paar generieren (Ed25519)
openclaw devices generate --json | jq '.deviceId, .publicKey, .privateKey'
```

Oder manuell (Go):

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	deviceId := base64.RawURLEncoding.EncodeToString(rand.Reader.Read(make([]byte, 32))) // 32 random bytes
	fmt.Printf("device_id: %s\n", deviceId)
	fmt.Printf("device_public_key: %s\n", base64.RawURLEncoding.EncodeToString(pub))
	fmt.Printf("device_private_key: %s\n", base64.RawURLEncoding.EncodeToString(append(priv[:32], priv[32:]...)))
}
```

**go run main.go** → kopiere die Ausgabe in `config.json`.

**Hinweis:** Die Keys sind **optional** — die Web-App funktioniert mit Token allein. Nur für **erweiterte Features** (z.B. Node-Control, Pairing) nötig.

## Schritt 4: config.json finalisieren

Beispiel (anpassen!):

```json
{
  "port": "8080",
  "ip_range": "0.0.0.0/0",
  "gateway_url": "http://localhost:18789",
  "gateway_token": "dein-aktualisiertes-gateway-token-hier",
  "device_id": "optional-device-id-aus-oben",
  "device_public_key": "optional-pubkey",
  "device_private_key": "optional-privkey-base64",
  "username": "admin",
  "password_hash": "base64-sha256-hash-deines-passworts",
  "openclaw_config": "/Users/christianotto/.openclaw/openclaw.json",
  "session_key": "agent:main:kiara-web",
  "display_name": "Kiara"
}
```

**Passwort-Hash generieren:**
```bash
echo -n "mein-sicheres-passwort" | openssl dgst -sha256 -binary | base64
```

## Schritt 5: Testen

### Gateway-Verbindung prüfen

```bash
# Health-Check
curl http://localhost:18789/health

# Erwartete Antwort: {"ok":true}
```

### Web-App starten (Test-Modus)

```bash
cd openclaw-web
go run . -config config.json
```

**Erfolgreiche Logs:**
```
[gw] connected
Starting Kiara on :8080 (allowed: 0.0.0.0/0)
Gateway: http://127.0.0.1:18789 | Session: agent:main:kiara-web
```

### Browser-Test

- Öffne `http://localhost:8080` (oder IP:Port).
- Login mit Username/Password.
- **Status:** Sollte "● Online" zeigen.
- **Model-Picker:** Sollte Models laden (sonst Gateway-Problem).

## Häufige Probleme

### ❌ "gw] error: failed to read JSON message"

**Ursache:** Gateway-Token falsch oder Gateway nicht erreichbar.

**Fix:**
1. Token prüfen: `jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json`
2. Gateway-URL testen: `curl http://<url>/health`
3. OpenClaw-Config prüfen: `openclaw doctor`

### ❌ "unauthorized" beim Login

**Ursache:** Password-Hash falsch.

**Fix:**
- Neuer Hash: `echo -n "passwort" | openssl dgst -sha256 -binary | base64`
- In `config.json` eintragen.
- `./openclaw-web` neu starten.

### ❌ Models laden nicht (leere Liste)

**Ursache:** `openclaw_config` Pfad falsch oder Gateway nicht connected.

**Fix:**
1. Pfad prüfen: `ls -la ~/.openclaw/openclaw.json`
2. Models manuell testen: `openclaw models list`
3. Logs prüfen: `tail -f openclaw-web.log`

### ❌ "connection refused" zu Gateway

**Ursache:** Gateway läuft nicht oder falscher Port/Host.

**Fix:**
1. Gateway-Status: `openclaw gateway status`
2. Gateway starten: `openclaw gateway start`
3. URL anpassen: `http://<ip>:18789` (nicht localhost, wenn remote).

### ❌ Vault-Fehler (optional)

**Ursache:** Vault geschlossen, aber `vault_enabled: true`.

**Fix:**
- Vault öffnen: `./usercommands/vaultctl unlock`
- Oder in `config.json`: `"vault_enabled": false`

## Erweiterte Konfiguration

### Mehrere Sessions

Die Web-App kann **verschiedene Sessions** verwalten (z.B. "Kiara", "Coding", "Home").

In `config.json`:
```json
{
  "session_key": "agent:main:kiara-web"
}
```

**Format:** `agent:<agent-id>:<session-name>`

- `agent-id`: z.B. `main` (Standard).
- `session-name`: Eigener Name (z.B. `kiara-web`, `coding-assistant`).

**Mehrere Sessions in OpenClaw:**
- In `~/.openclaw/openclaw.json`: `"agents": { "main": { ... }, "coding": { ... } }`
- Sessions pro Agent: `~/.openclaw/agents/<agent-id>/sessions/sessions.json`

### IP-Range einschränken

Sicherheit: Nur bestimmte IPs erlauben.

```json
{
  "ip_range": "10.9.9.0/24"  // Dein LAN
}
```

**Für öffentlichen Zugriff:** `"ip_range": "0.0.0.0/0"` (nicht empfohlen ohne HTTPS).

### HTTPS (Reverse Proxy)

Mit Nginx/Caddy als Proxy:

**Nginx-Beispiel:**
```
server {
    listen 443 ssl;
    server_name openclaw.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## Deployment-Beispiele

### Raspberry Pi (Pi 5)

1. **OpenClaw installieren:** Siehe OpenClaw-Docs.
2. **Gateway starten:** `openclaw gateway start`
3. **Web-App:** 
   ```bash
   cd openclaw-web
   go build -o openclaw-web .
   nohup ./openclaw-web &
   ```
4. **Firewall:** Port 8080 öffnen (ufw/nginx).
5. **Zugriff:** `http://<pi-ip>:8080`

### VPS / Server

1. **OpenClaw:** `npm i -g openclaw`
2. **Gateway:** `openclaw gateway start --bind tailnet`
3. **Web-App:** Go-Binary kompilieren + systemd-Service.
4. **Domain:** Nginx-Proxy + Let's Encrypt.

### Laptop / Development

1. **Gateway:** `openclaw gateway start --bind loopback`
2. **Web-App:** `go run .` (im Projekt-Ordner).
3. **Zugriff:** Nur lokal (`http://localhost:8080`).

## Logs + Debugging

### Web-App Logs

```bash
# Aktuelle Logs
tail -f openclaw-web.log

# Gateway-Verbindung prüfen
grep "\[gw\]" openclaw-web.log
```

**Erfolgreich:**
```
[gw] connected
[models] loaded 21 models via openclaw CLI (merge mode)
```

### OpenClaw Gateway Logs

```bash
# Gateway-Logs
openclaw gateway log

# Vollständig
tail -f ~/.openclaw/logs/gateway.log
```

## Nächste Schritte

1. **Starten:** `./openclaw-web`
2. **Login:** Mit Username/Password.
3. **Test:** Model-Picker öffnen → Models laden.
4. **Produktion:** systemd-Service einrichten.

Falls Probleme: `openclaw doctor` + `openclaw gateway status` laufen lassen und die Ausgabe teilen!

---
*Erstellt: 2026-02-20 | Letzte Änderung: 2026-02-20*
