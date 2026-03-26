# openclaw-web – Feature Roadmap / TODO

Stand: 2026-03-26

## Kontext / Arbeitsweise

- Prod-Deployment liegt unter `~/.openclaw/openclaw-web` und soll während der Entwicklung **nicht** angefasst werden.
- Dev-Working-Copy (temporär): `~/ .openclaw/workspace/tmp/openclaw-web-dev`
- Ziel: Erst wenn Dev-Version stabil ist → Prod ersetzen.

## Implementiert (Dev)

### 1) Bilder im Chat anzeigen (Assistant → Web UI)

- UI rendert Bilder, wenn in einer Message eine Zeile vorkommt:
  - `MEDIA:/absoluter/pfad/zum/bild.png`
- Server liefert Bild via `/media?path=...`
- Allowlist Roots (Sicherheit):
  - `~/.openclaw/workspace`, `~/.openclaw/media`, `~/.openclaw/tmp`

### 2) Bild-Upload (Web UI → Assistant) – Basis

- UI: ＋ Button, aktuell 1 Bild, max 5 MB
- API: `/api/chat` unterstützt `attachments: [{name,mimeType,content(base64)}]`
- Server: bei Attachments wird Gateway-Methode `agent` genutzt (statt `chat.send`)

## Known Issues

### A) MEDIA-Bild erscheint teils erst nach Refresh

- Symptom: Nach Antwort mit `MEDIA:` wird Bild erst sichtbar nach manuellem Refresh.
- TODO:
  - SSE-Pfad vs. non-SSE Pfad prüfen: wird `addMessage`/parseMediaLines wirklich in beiden Pfaden verwendet?
  - Sicherstellen, dass beim Empfang einer Assistant-Message die DOM-Update-Reihenfolge nicht das Image-Append „verliert“.
  - Reproduzierbaren Test bauen: Assistant antwortet mit `MEDIA:` + sofortigem Image-Load.

## Next Steps (kurzfristig)

1) **Fix:** MEDIA-Rendering ohne Refresh (Blocker)
2) **Test:** Upload-Richtung (Bild anhängen → Modell analysiert das Bild → Antwort zeigt Analyse)
3) UX:
   - Attachment-Preview statt einer extra „[Bild angehängt…]“ Chatmessage
   - Multi-Attachments (mehrere Bilder)
   - Drag&Drop

## Geplante Features (mittel-/langfristig)

- **Browser Speech-to-Text** (Spracheingabe)
- **Browser TTS** (Sprachausgabe)
- **WhatsApp Statusanzeige** (connected / logged out / last check)
- **Logging/Debug** Verbesserungen (Filter, Export, weniger Noise)
- **Session-Protokoll Analyse** (Zusammenfassungen, Suche, Insights, ggf. Export)
