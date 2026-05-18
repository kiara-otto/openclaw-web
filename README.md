# OpenClaw Web

Einfaches Web-Interface für OpenClaw.

## Installation

### 1. Klonen

```bash
# entweder euer eigenes Repo/Fork …
git clone <REPO_URL>
cd openclaw-web
```

### 2. Go installieren

Go **1.25.6** oder höher erforderlich.

- **macOS:** `brew install go`
- **Linux:** Siehe https://go.dev/doc/install
- **Raspberry Pi:** `GOOS=linux GOARCH=arm64` Binary von go.dev herunterladen

### 3. Abhängigkeiten installieren

```bash
go mod download
```

### 4. Konfiguration erstellen

Nach dem Klonen die `config.json` erstellen:

```bash
cp config.json.example config.json
```

#### Gateway-Verbindung einrichten

Die Web-App verbindet sich als Operator-Client mit eurem OpenClaw Gateway. **Kein Pairing/Approval erforderlich** — die App authentifiziert sich direkt mit dem Gateway-Token.

**⚠️ Wichtig:** Euer OpenClaw Gateway muss korrekt konfiguriert sein! Siehe **[GATEWAY-SETUP.md](GATEWAY-SETUP.md)** für detaillierte Anweisungen und Troubleshooting.

**🎯 Typisches Setup (Raspberry Pi):**

Beide Programme laufen auf dem **gleichen Gerät** (z.B. Raspberry Pi):
- OpenClaw Gateway: `localhost:18789` (nur lokal erreichbar)
- Web-App: Port `8080` (von außen erreichbar, spricht Gateway über `localhost` an)
- Benutzer-Zugriff: `http://<raspberry-ip>:8080`

**Kurzanleitung:**

**Schritt 1: Gateway-Token finden**

Das Token findet ihr in eurer OpenClaw-Config (`~/.openclaw/openclaw.json`):

```bash
# Token anzeigen
cat ~/.openclaw/openclaw.json | grep -A2 '"token"'
```

Oder mit `jq`:
```bash
jq -r '.gateway.token' ~/.openclaw/openclaw.json
```

Das Token kopiert ihr in `config.json` unter `gateway_token`.

**Schritt 2: Gateway-URL ermitteln**

Standard-URL: `http://localhost:18789`

Wenn euer Gateway auf einem anderen Host läuft, findet ihr die URL in der OpenClaw-Config:
```bash
jq -r '.gateway.url' ~/.openclaw/openclaw.json
```

**Schritt 3: `config.json` anpassen**

Dann die `config.json` anpassen:

| Feld | Pflicht | Beschreibung |
|------|---------|--------------|
| `port` | ✅ | Port für den Webserver (z.B. `8080`) |
| `ip_range` | ✅ | Erlaubte IP-Range z.B. `10.9.9.0/24` oder `0.0.0.0/0` |
| `gateway_url` | ✅ | URL eures OpenClaw Gateways (siehe oben, Standard: `http://localhost:18789`) |
| `gateway_token` | ✅ | Gateway-Token aus eurer `openclaw.json` (siehe oben) |
| `username` | ✅ | Login-Benutzername |
| `password_hash` | ✅ | **SHA-256 Hash des Passworts** (Base64-kodiert, siehe unten) |
| `openclaw_config` | ❌ | Pfad zur OpenClaw-Config. **Standard:** `$HOME/.openclaw/openclaw.json`. Nur nötig wenn eure Config woanders liegt. |
| `session_key` | ❌ | Session-Key im Format `agent:main:<Name>`. **Beispiel:** `agent:main:wohnzimmer` oder `agent:main:mein-assistant`. **Das `:Name` am Ende ist zwingend erforderlich!** Standard: `agent:main:openclaw-web`. |
| `display_name` | ❌ | Anzeigename des Assistants (Default: wird aus session_key abgeleitet) |
| `vault_enabled` | ❌ | Vault-Steuerung im Menü anzeigen (`true`/`false`). **Standard:** `true`. Auf `false` setzen wenn kein OpenClaw Vault vorhanden. |

#### Passwort-Hash erzeugen

```bash
echo -n "DEIN_PASSWORT" | openssl dgst -sha256 -binary | base64
```

Das Ergebnis in `password_hash` eintragen.

#### Verbindung testen

Nach dem Start der Web-App sollte im Log erscheinen:
```
[gw] connected
```

Falls nicht, siehe **[GATEWAY-SETUP.md](GATEWAY-SETUP.md)** für detailliertes Troubleshooting!

**Hinweis nach OpenClaw-Updates:** Der aktuelle Gateway-Handshake läuft auf **Protocol v4**. Wenn nach einem OpenClaw-Update `protocol mismatch` im Log steht, muss `openclaw-web` gegen die neue Gateway-Version neu gebaut werden.

## Troubleshooting

Probleme mit der Gateway-Verbindung? Siehe **[GATEWAY-SETUP.md](GATEWAY-SETUP.md)** für:

- ✅ Minimale OpenClaw-Config-Anforderungen
- 🔧 Bind-Modus konfigurieren (loopback vs. network)
- 🐛 Häufige Fehler und Lösungen
- 🎯 Schnell-Check-Liste
- 📋 Vollständige Config-Beispiele

**Kurz-Check:**

```bash
# Gateway läuft?
openclaw status

# Gateway-Token anzeigen
jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json

# Gateway-Verbindung testen
curl http://localhost:18789/health
# Sollte antworten: {"ok":true}
```

**Erfolgreiche Verbindung:**

Im Web-App-Log sollte stehen:
```
[gw] connected
```

## Kompilieren

```bash
# macOS / amd64
go build -o openclaw-web ./cmd/server

# Raspberry Pi 5 / arm64
GOOS=linux GOARCH=arm64 go build -o openclaw-web-arm64 ./cmd/server
```

## Lokaler Test-Checkout

Für einen sicheren Testlauf neben der produktiven Instanz:

```bash
cp /path/to/your/current/openclaw-web/config.json config.test.json
jq '.port = "8081" | .session_key = "agent:main:kiara-web-test" | .display_name = "Kiara Test"' config.test.json > /tmp/openclaw-web-config && mv /tmp/openclaw-web-config config.test.json
go run ./cmd/server --config config.test.json
```

So bleibt die Hauptinstanz auf `8080` unangetastet, während der Test-Server auf `8081` läuft.

## Server starten

```bash
# Im Vordergrund
go run ./cmd/server --config config.json

# Oder im Hintergrund (Linux/macOS mit LaunchD)
# Die PID wird in openclaw-web.pid gespeichert
nohup ./openclaw-web --config config.json & echo $! > openclaw-web.pid
```

## Server stoppen

```bash
# Mit der PID-Datei (falls gestartet wie oben)
kill $(cat openclaw-web.pid)
rm openclaw-web.pid

# Oder direkt
pkill openclaw-web
```

## Passwort ändern

Das Passwort wird **nicht** im Klartext gespeichert, sondern als SHA-256 Hash. Um es zu ändern:

1. Neuen Hash erzeugen:
   ```bash
   echo -n "NEUES_PASSWORT" | openssl dgst -sha256 -binary | base64
   ```

2. Den neuen Hash in `config.json` bei `password_hash` eintragen.

3. Service neu starten.
