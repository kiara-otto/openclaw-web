# OpenClaw Web-App Setup & Troubleshooting Guide

Komplette Schritt-für-Schritt-Anleitung zur Einrichtung der openclaw-web App mit allen notwendigen Checks und Troubleshooting-Schritten.

**Repo:** <REPO_URL> (z.B. euer Fork / eure interne Gitea-URL)

## 🎯 Übersicht

Die Web-App verbindet sich als **Operator-Client** direkt mit dem OpenClaw Gateway (WebSocket). Kein Pairing/Approval erforderlich.

**Setup-Szenarien:**

### Szenario A: Alles auf einem Gerät (z.B. Raspberry Pi)
```
┌─────────────────────────────────────┐
│  Raspberry Pi (192.168.1.50)        │
│                                     │
│  OpenClaw Gateway :18789            │
│         ↕ (localhost)               │
│  Web-App :8080                      │
└─────────────────────────────────────┘
         ↑
    Browser von außen
  (http://192.168.1.50:8080)
```

**Config:**
- OpenClaw: `bind: "loopback"`
- Web-App: `gateway_url: "http://localhost:18789"`

### Szenario B: Gateway auf anderem Server
```
┌──────────────────┐      ┌──────────────────┐
│  Raspberry Pi    │      │  Desktop-PC      │
│  Web-App :8080   │──────│  Gateway :18789  │
│                  │ LAN  │                  │
└──────────────────┘      └──────────────────┘
```

**Config:**
- OpenClaw: `bind: "network"`
- Web-App: `gateway_url: "http://192.168.1.X:18789"`

---

## 📋 Schritt 1: OpenClaw Gateway prüfen

### 1.1 Gateway läuft?

```bash
openclaw status
```

**Erwartete Ausgabe:**
```
✓ Gateway running (PID: 12345)
  Port: 18789
  Mode: local
```

**Falls nicht:** Gateway starten:
```bash
openclaw gateway start
```

---

### 1.2 Gateway-Config prüfen

```bash
jq '.gateway' ~/.openclaw/openclaw.json
```

**Minimal erforderliche Config:**
```json
{
  "port": 18789,
  "mode": "local",
  "bind": "loopback",
  "auth": {
    "mode": "token",
    "token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09"
  }
}
```

**Wichtige Felder:**

| Feld | Bedeutung | Wert für Szenario A | Wert für Szenario B |
|------|-----------|---------------------|---------------------|
| `bind` | Wo Gateway hört | `"loopback"` | `"network"` |
| `port` | Gateway-Port | `18789` | `18789` |
| `auth.token` | Authentifizierung | (gleicher Token in Web-App) | (gleicher Token in Web-App) |

**Falls `bind` fehlt:** Standard ist `"loopback"` (nur localhost erreichbar).

---

### 1.3 Token extrahieren

```bash
jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json
```

**Ausgabe:** Der Token (z.B. `939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09`)

**Diesen Token** brauchst du für die Web-App `config.json`!

---

### 1.4 Gateway-Verbindung testen (lokal)

```bash
curl http://localhost:18789/health
```

**Erwartete Ausgabe:**
```json
{"ok":true}
```

**Fehler?**
- `Connection refused` → Gateway läuft nicht (siehe 1.1)
- `Timeout` → Firewall/Port blockiert

---

### 1.5 Gateway-Verbindung testen (von außen) – nur Szenario B!

**Falls Web-App auf anderem Gerät läuft:**

```bash
# IP-Adresse des Gateway-Hosts ermitteln
ifconfig | grep "inet " | grep -v 127.0.0.1
# oder
ip addr show | grep "inet " | grep -v 127.0.0.1
```

**Von anderem Gerät aus testen:**
```bash
curl http://192.168.1.50:18789/health
```

**Fehler `Connection refused`?**
→ `bind: "loopback"` muss auf `"network"` geändert werden!

---

## 📋 Schritt 2: Web-App Config prüfen

### 2.1 Config-Datei anzeigen

```bash
cd ~/openclaw-web  # oder wo auch immer die App liegt
cat config.json
```

---

### 2.2 Minimal erforderliche Config (Szenario A)

```json
{
  "port": "8080",
  "ip_range": "0.0.0.0/0",
  "gateway_url": "http://localhost:18789",
  "gateway_token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09",
  "username": "admin",
  "password_hash": "jGl25bVBBBW96Qi9Te4V37Fnqchz/Eu4qB9vKrRIqRg=",
  "session_key": "agent:main:openclaw-web",
  "display_name": "OpenClaw Web"
}
```

**Wichtige Felder:**

| Feld | Bedeutung | Beispiel |
|------|-----------|----------|
| `gateway_url` | Gateway-URL | `http://localhost:18789` (Szenario A) oder `http://192.168.1.50:18789` (Szenario B) |
| `gateway_token` | Token aus OpenClaw-Config | (siehe Schritt 1.3) |
| `password_hash` | SHA-256 Hash des Web-Passworts | Siehe unten |
| `session_key` | OpenClaw Session | `agent:main:<Name>` (`:Name` am Ende zwingend!) |

---

### 2.3 Passwort-Hash erzeugen

```bash
echo -n "DEIN_PASSWORT" | openssl dgst -sha256 -binary | base64
```

**Beispiel:**
```bash
echo -n "admin123" | openssl dgst -sha256 -binary | base64
# Ausgabe: jGl25bVBBBW96Qi9Te4V37Fnqchz/Eu4qB9vKrRIqRg=
```

Diesen Hash in `config.json` unter `password_hash` eintragen.

---

### 2.4 Config validieren

```bash
cat config.json | jq .
```

**Keine Fehler?** → Config ist gültiges JSON ✅

**Fehler?**
- `parse error` → Komma/Klammer fehlt
- `jq: command not found` → `jq` installieren: `sudo apt install jq` (Raspberry Pi)

---

## 📋 Schritt 3: Web-App starten

### 3.1 Dependencies installieren

```bash
cd ~/openclaw-web
go mod download
```

---

### 3.2 App starten (Foreground)

```bash
go run ./cmd/server --config config.json
```

**Erwartete Ausgabe:**
```
[gw] connected
Starting openclaw-web on :8080 (allowed: 0.0.0.0/0)
Gateway: http://localhost:18789 | Session: agent:main:openclaw-web
```

✅ **"[gw] connected"** → Gateway-Verbindung steht!

**Wenn stattdessen `protocol mismatch` im Log steht:** Das Binary spricht eine alte Gateway-Protokollversion. Für aktuelle OpenClaw-Builds muss `internal/gateway/client.go` auf **Protocol v4** gebaut werden.

---

## ❌ Troubleshooting

### Fehler: "connection refused" beim Start

**Symptom:**
```
dial tcp 127.0.0.1:18789: connect: connection refused
```

**Ursache:** Gateway nicht erreichbar

**Lösung:**
1. Gateway läuft? → `openclaw status`
2. Port korrekt? → `jq '.gateway.port' ~/.openclaw/openclaw.json`
3. Falls Gateway auf anderem Host: `gateway_url` in `config.json` anpassen

---

### Fehler: "Error origin not allowed"

**Symptom:**
```
Error origin not allowed
```

**Ursache:** WebSocket-Handshake schlägt fehl (meist falsche URL oder bind-Modus)

**Lösung:**

**Szenario A (beide auf gleichem Host):**
```bash
# Prüfen:
cat config.json | jq -r '.gateway_url'
# Sollte sein: http://localhost:18789

# Falls falsch:
nano config.json
# Ändern zu: "gateway_url": "http://localhost:18789"
```

**Szenario B (Web-App auf anderem Host):**
```bash
# 1. OpenClaw Gateway auf "network" setzen
nano ~/.openclaw/openclaw.json
# Unter "gateway" -> "bind" ändern zu: "network"

# 2. Gateway neu starten
openclaw gateway restart

# 3. Web-App config.json anpassen
nano ~/openclaw-web/config.json
# "gateway_url" ändern zu: "http://192.168.1.50:18789" (IP des Gateway-Hosts)
```

---

### Fehler: "unauthorized" / "authentication error"

**Symptom:**
```
[gw] error: Authentication error
```

**Ursache:** Token stimmt nicht überein

**Lösung:**
```bash
# 1. Token aus OpenClaw-Config holen
jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json

# 2. In Web-App config.json eintragen
nano ~/openclaw-web/config.json
# "gateway_token" auf exakt den gleichen Wert setzen

# 3. Web-App neu starten
go run ./cmd/server --config config.json
```

---

### Fehler: Gateway zeigt "Gateway not connected" im Web-Interface

**Ursache:** WebSocket-Verbindung bricht ab

**Lösung:**
```bash
# 1. Gateway-Logs prüfen
tail -50 ~/.openclaw/logs/gateway.log

# 2. Web-App-Logs prüfen
tail -50 ~/openclaw-web/openclaw-web.log

# 3. Token + URL nochmal kontrollieren
cat ~/openclaw-web/config.json | jq -r '.gateway_url, .gateway_token'
```

---

### Fehler: "protocol mismatch"

**Ursache:** `openclaw-web` und Gateway verwenden unterschiedliche WebSocket-Protokollversionen.

**Lösung:**
```bash
# 1. Web-App neu bauen
go build -o openclaw-web ./cmd/server

# 2. Sicherstellen, dass der Client Protocol v4 anfragt
rg -n 'minProtocol|maxProtocol' internal/gateway/client.go

# 3. Web-App neu starten und Logs erneut prüfen
go run ./cmd/server --config config.json
```

---

### Fehler: Web-Interface von außen nicht erreichbar

**Symptom:** Browser zeigt "Connection refused" beim Aufruf von `http://192.168.1.50:8080`

**Ursache:** Firewall oder ip_range blockiert

**Lösung:**
```bash
# 1. Web-App läuft?
ps aux | grep openclaw-web

# 2. Port lauscht?
netstat -tuln | grep 8080
# oder
ss -tuln | grep 8080

# 3. Firewall prüfen (Raspberry Pi/Debian)
sudo ufw status
# Falls Port geblockt:
sudo ufw allow 8080/tcp

# 4. ip_range prüfen
cat ~/openclaw-web/config.json | jq -r '.ip_range'
# Sollte sein: "0.0.0.0/0" (alle IPs erlaubt)
```

---

## 🎯 Erfolgreiche Verbindung checken

### Check 1: Web-App-Log

```bash
tail -20 ~/openclaw-web/openclaw-web.log
```

**Sollte enthalten:**
```
[gw] connected
Starting openclaw-web on :8080
```

---

### Check 2: Gateway-Log

```bash
tail -20 ~/.openclaw/logs/gateway.log
```

**Sollte enthalten:**
```
[ws] operator connected: id=gateway-client role=operator
```

---

### Check 3: Browser

1. Browser öffnen: `http://192.168.1.50:8080` (IP des Raspberry Pi)
2. Login mit `username` / `password` aus `config.json`
3. Status in der Web-App → "Connected" sollte grün sein

---

## 📦 Produktiv-Deployment

### Option A: systemd Service (empfohlen)

```bash
# 1. Binary kompilieren
cd ~/openclaw-web
go build -o openclaw-web ./cmd/server

# 2. Systemd-Service erstellen
sudo nano /etc/systemd/system/openclaw-web.service
```

**Service-Datei:**
```ini
[Unit]
Description=OpenClaw Web Interface
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/openclaw-web
ExecStart=/home/pi/openclaw-web/openclaw-web
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# 3. Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable openclaw-web
sudo systemctl start openclaw-web

# 4. Status prüfen
sudo systemctl status openclaw-web
```

---

### Option B: Screen/tmux (quick & dirty)

```bash
# Screen-Session starten
screen -S openclaw-web

# Web-App starten
cd ~/openclaw-web
./openclaw-web

# Session detachen: Ctrl+A, dann D
# Wieder anhängen: screen -r openclaw-web
```

---

## 🔒 Sicherheit

### 1. IP-Range einschränken

Nur lokales Netzwerk erlauben:
```json
{
  "ip_range": "192.168.1.0/24"
}
```

---

### 2. Starkes Passwort verwenden

```bash
# Sicheres Passwort generieren (20 Zeichen)
openssl rand -base64 20

# Hash erzeugen
echo -n "GENERIERTES_PASSWORT" | openssl dgst -sha256 -binary | base64
```

---

### 3. Gateway-Token rotieren (optional)

```bash
# Neuen Token erzeugen (32 Bytes = 64 Hex-Zeichen)
openssl rand -hex 32

# In ~/.openclaw/openclaw.json eintragen
nano ~/.openclaw/openclaw.json
# "gateway.auth.token" auf neuen Wert setzen

# Gateway neu starten
openclaw gateway restart

# Web-App config.json aktualisieren
nano ~/openclaw-web/config.json
# "gateway_token" auf neuen Wert setzen

# Web-App neu starten
sudo systemctl restart openclaw-web
```

---

## 📞 Support-Checklist

Falls es immer noch nicht klappt, sammle diese Infos:

```bash
# 1. OpenClaw-Version
openclaw --version

# 2. Gateway-Status
openclaw status

# 3. Gateway-Config
jq '.gateway' ~/.openclaw/openclaw.json

# 4. Web-App Config (ohne Secrets)
jq 'del(.gateway_token, .password_hash)' ~/openclaw-web/config.json

# 5. Gateway-Log (letzte 50 Zeilen)
tail -50 ~/.openclaw/logs/gateway.log

# 6. Web-App-Log (letzte 50 Zeilen)
tail -50 ~/openclaw-web/openclaw-web.log

# 7. Netzwerk-Check
netstat -tuln | grep -E "8080|18789"
```

---

## ✅ Quick-Reference

**Erfolgreiche Verbindung erkennen:**
- ✅ `openclaw status` → Gateway läuft
- ✅ `curl http://localhost:18789/health` → `{"ok":true}`
- ✅ Web-App-Log: `[gw] connected`
- ✅ Gateway-Log: `[ws] operator connected`
- ✅ Web-Interface: Status "Connected" (grün)

**Typische Fehlerquellen:**
- ❌ Gateway läuft nicht
- ❌ Token stimmt nicht überein
- ❌ `bind: "loopback"` bei externem Zugriff
- ❌ `gateway_url` zeigt auf falsche IP
- ❌ Firewall blockiert Port 8080 oder 18789

---

Viel Erfolg! 🚀
