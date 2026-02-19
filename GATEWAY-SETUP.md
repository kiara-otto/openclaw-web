# Gateway-Setup für kiara-web

## ✅ Minimale OpenClaw-Config-Anforderungen

Damit die Web-App funktioniert, muss eure `~/.openclaw/openclaw.json` folgende Gateway-Einstellungen haben:

### 1. Gateway muss aktiviert sein

```json
{
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",  // oder "network" (siehe unten)
    "auth": {
      "mode": "token",
      "token": "EUER_GATEWAY_TOKEN_HIER"
    }
  }
}
```

### 2. Bind-Modus wählen

**Wichtig:** Der `bind`-Modus entscheidet, WO die Web-App laufen kann:

| Szenario | `bind`-Wert | Gateway-URL in `config.json` |
|----------|-------------|------------------------------|
| Web-App läuft auf **gleichem Computer** wie OpenClaw (z.B. beide auf Raspberry Pi) | `"loopback"` | `http://localhost:18789` |
| Web-App läuft auf **anderem Gerät** als OpenClaw (z.B. Web-App auf PC, OpenClaw auf Server) | `"network"` | `http://<IP-DES-OPENCLAW-HOSTS>:18789` |

**Standard ist `loopback`** → funktioniert nur lokal!

**📍 Typisches Setup (Raspberry Pi):**
```
┌─────────────────────────────────────┐
│  Raspberry Pi (z.B. 192.168.1.50)   │
│                                     │
│  ┌─────────────┐                   │
│  │  OpenClaw   │◄─────localhost────┤
│  │  :18789     │                   │
│  └─────────────┘                   │
│         ▲                           │
│         │ localhost                │
│         ▼                           │
│  ┌─────────────┐                   │
│  │  Web-App    │                   │
│  │  :8080      │◄────Benutzer von außen (http://192.168.1.50:8080)
│  └─────────────┘                   │
└─────────────────────────────────────┘

Config: bind: "loopback", gateway_url: "http://localhost:18789"
```

### 3. Config ändern (falls nötig)

```bash
# 1. OpenClaw stoppen
openclaw gateway stop

# 2. Config bearbeiten
nano ~/.openclaw/openclaw.json

# 3. Unter "gateway" -> "bind" ändern zu "network":
"gateway": {
  "bind": "network",
  ...
}

# 4. Gateway neu starten
openclaw gateway start

# 5. Prüfen ob Gateway läuft
openclaw status
```

## 🔍 Gateway-Status prüfen

```bash
# Gateway läuft?
openclaw status

# Gateway-Logs ansehen
tail -f ~/.openclaw/logs/gateway.log

# Gateway-Verbindung testen (von anderem Gerät)
curl http://<IP-ADRESSE>:18789/health
# Sollte antworten mit: {"ok":true}
```

## 📋 Vollständige Config-Beispiele

**Wichtig zu verstehen:**

- **`bind: "loopback"`** → Gateway hört nur auf `127.0.0.1` (localhost)
  - ✅ Web-App auf **gleichem** Host kann verbinden
  - ❌ Web-App auf **anderem** Host kann NICHT verbinden

- **`bind: "network"`** → Gateway hört auf allen Netzwerk-Interfaces
  - ✅ Web-App auf gleichem Host kann verbinden
  - ✅ Web-App auf anderem Host kann verbinden (über LAN-IP)

### Beispiel 1: Web-App läuft LOKAL (gleicher Computer, z.B. Raspberry Pi)

**Szenario:** OpenClaw + Web-App laufen beide auf dem Raspberry Pi. Benutzer greifen von außen auf die Web-App zu (z.B. `http://192.168.1.50:8080`), aber intern spricht die Web-App mit OpenClaw über `localhost`.

**`~/.openclaw/openclaw.json` (auf dem Raspberry Pi):**
```json
{
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09"
    }
  }
}
```

**`config.json` der Web-App (ebenfalls auf dem Raspberry Pi):**
```json
{
  "port": "8080",
  "ip_range": "0.0.0.0/0",
  "gateway_url": "http://localhost:18789",
  "gateway_token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09",
  "session_key": "agent:main:kiara-web"
}
```

**Zugriff von außen:** `http://192.168.1.50:8080` (IP des Raspberry)

### Beispiel 2: Web-App läuft auf ANDEREM GERÄT (z.B. Raspberry Pi)

**OpenClaw-Host (z.B. Mac/PC mit IP 192.168.1.100):**

**`~/.openclaw/openclaw.json`:**
```json
{
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "network",
    "auth": {
      "mode": "token",
      "token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09"
    }
  }
}
```

**Web-App (z.B. auf Raspberry Pi):**

**`config.json`:**
```json
{
  "gateway_url": "http://192.168.1.100:18789",
  "gateway_token": "939572c3d66a2293ebee19e0734ba4bbc7d8876158710d09"
}
```

## ⚠️ Häufige Fehler

### Fehler: "connection refused"

**Ursache:** Gateway nicht erreichbar

**Lösung:**
1. Gateway läuft? → `openclaw status`
2. Richtiger `bind`-Modus? → siehe Tabelle oben
3. Firewall blockiert Port 18789?

### Fehler: "unauthorized" / "authentication error"

**Ursache:** Token falsch oder fehlt

**Lösung:**
1. Token aus `~/.openclaw/openclaw.json` kopieren
2. Exakt in Web-App `config.json` unter `gateway_token` eintragen
3. Web-App neu starten

### Fehler: "Gateway not connected" im Web-Interface

**Ursache:** WebSocket-Verbindung scheitert

**Lösung:**
1. Gateway-Logs prüfen: `tail -f ~/.openclaw/logs/gateway.log`
2. Web-App-Logs prüfen: `tail -f openclaw-web.log`
3. Token und URL nochmal kontrollieren

## 🎯 Schnell-Check

**Führe diese Befehle auf dem Host aus (wo OpenClaw läuft):**

```bash
# 1. Gateway läuft?
openclaw status

# 2. Gateway-Config anzeigen
jq '.gateway' ~/.openclaw/openclaw.json

# 3. Token anzeigen
jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json

# 4. Gateway-Verbindung testen (lokal)
curl http://localhost:18789/health
# Sollte antworten: {"ok":true}
```

**Falls Web-App auf ANDEREM Gerät läuft:**

```bash
# IP-Adresse des OpenClaw-Hosts ermitteln
ifconfig | grep "inet " | grep -v 127.0.0.1
# oder
ip addr show | grep "inet " | grep -v 127.0.0.1

# Von anderem Gerät aus Gateway testen:
curl http://<IP-ADRESSE>:18789/health
# z.B.: curl http://192.168.1.50:18789/health
```

Wenn alle Tests funktionieren, sollte die Web-App verbinden können!

## 🔒 Sicherheit

Bei `bind: "network"` ist das Gateway im lokalen Netzwerk erreichbar. Schützt den Zugang:

1. **IP-Range** in Web-App `config.json` beschränken:
   ```json
   "ip_range": "192.168.1.0/24"
   ```

2. **Starkes Token** verwenden (mindestens 32 Zeichen)

3. **Firewall-Regel** (nur aus lokalem Netzwerk):
   ```bash
   # macOS (falls gewünscht)
   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /opt/homebrew/bin/openclaw
   ```

## ❓ Häufige Fragen

### Beide laufen auf dem Raspberry Pi — warum kann ich die Web-App von meinem PC aus aufrufen?

**Antwort:** Die Web-App ist ein **HTTP-Server** auf Port 8080, der von außen erreichbar ist (das regelt `ip_range` in der Web-App-Config). Die **interne Kommunikation** zwischen Web-App und OpenClaw-Gateway läuft aber über `localhost:18789` auf dem Raspberry Pi selbst.

```
Du (PC) ──HTTP (8080)──> Raspberry Pi (Web-App)
                              │
                              └──WebSocket (localhost:18789)──> OpenClaw Gateway
```

### Muss ich `bind: "network"` verwenden, wenn ich die Web-App von außen aufrufe?

**Nein!** Wenn Web-App und OpenClaw auf dem **gleichen Host** laufen, reicht `bind: "loopback"`. Die Web-App spricht OpenClaw intern über `localhost` an. Nur **du** greifst von außen auf die Web-App zu (Port 8080), nicht auf das Gateway (Port 18789).

### Wann brauche ich `bind: "network"`?

Nur wenn OpenClaw und Web-App auf **verschiedenen Geräten** laufen:

- **OpenClaw:** Server/Desktop (IP: 192.168.1.100)
- **Web-App:** Raspberry Pi (IP: 192.168.1.50)
- **Web-App config.json:** `"gateway_url": "http://192.168.1.100:18789"`

In diesem Fall muss das Gateway auf dem Server mit `bind: "network"` laufen.

## 📞 Support

Falls es immer noch nicht klappt, sammle diese Infos:

```bash
# 1. OpenClaw-Version
openclaw --version

# 2. Gateway-Status
openclaw status

# 3. Gateway-Config
jq '.gateway' ~/.openclaw/openclaw.json

# 4. Letzte 20 Zeilen Gateway-Log
tail -20 ~/.openclaw/logs/gateway.log

# 5. Web-App-Log (erste Connection-Versuche)
tail -50 openclaw-web.log | grep -A5 -B5 "gw"
```

Dann kann man gezielt debuggen!
