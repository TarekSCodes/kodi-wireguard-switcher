# service.wireguard.switcher

Kodi-Addon, das WireGuard-VPN-Server per Fernbedienungstaste wechselt und beim Kodi-Start automatisch den zuletzt verwendeten Server wiederherstellt.

> **Plattform:** Linux erforderlich. Das Addon ruft `wg-quick` und `wg` auf — beides sind Linux-Kommandozeilentools. Auf Windows-Kodi startet das Addon zwar, der VPN-Wechsel schlägt jedoch fehl, da diese Binaries dort nicht verfügbar sind.

---

## Voraussetzungen

- Kodi auf **Linux** (getestet mit LibreELEC 12 / Kodi 21)
- `wg-quick` und `wg` unter `/usr/bin/` verfügbar (in LibreELEC 12 nativ im Kernel eingebaut)
- WireGuard-Configs vom VPN-Anbieter (getestet mit HideMe)
- Python 3 auf dem Entwicklungsrechner

---

## Projektstruktur

```
service.wireguard.switcher/
├── addon.xml                   Kodi-Addon-Manifest
├── service.py                  Hintergrundservice (startet mit Kodi)
├── switch.py                   Script für Tastendruck (VPN-Wechsel)
├── resources/
│   ├── settings.xml            Addon-Einstellungen in Kodi
│   └── lib/
│       ├── wg_manager.py       Core-Logik: wg-quick, State, Config-Cycling
│       ├── notifier.py         Kodi-Notification-Wrapper
│       ├── button_learner.py   Dialog zum Erlernen einer Fernbedienungstaste
│       └── keymap_manager.py   Schreibt die Keymap-XML und lädt sie neu
├── configs/                    WireGuard .conf-Dateien (gitignored!)
│   └── README.txt              Regeln für Dateinamen
├── keymaps/
│   └── wireguard.xml           Generierte Keymap (wird zur Laufzeit überschrieben)
├── deploy.py                   SFTP-Deploy-Script
├── requirements.txt            Entwicklungs-Abhängigkeiten
└── .gitignore
```

---

## Funktionsweise

### Beim Kodi-Start (`service.py`)

`service.py` ist als `xbmc.service` registriert und startet automatisch nach dem Login. Es:

1. Stellt die zuletzt konfigurierte Fernbedienungstaste aus `state.json` wieder her (Keymap neu schreiben)
2. Verbindet den zuletzt verwendeten WireGuard-Server (`restore()`)
3. Läuft in einer Schleife und prüft alle 30 Sekunden, ob der Tunnel noch aktiv ist — falls nicht, reconnectet er automatisch

`waitForAbort(1)` statt `time.sleep()` sorgt dafür, dass der Service sofort auf ein Kodi-Shutdown-Signal reagiert. Der Tunnel bleibt nach Kodi-Exit aktiv.

### Beim Tastendruck (`switch.py`)

`switch.py` ist als `xbmc.python.script` registriert und wird von der Keymap ausgelöst. Es läuft als eigener kurzlebiger Prozess — ein Absturz killt nicht den Monitor-Service.

Beim Aufruf ohne Argumente: Aktuellen Tunnel trennen → nächste Config in der alphabetisch sortierten Liste aktivieren → in `state.json` speichern.

Beim Aufruf mit Argument `learn`: Button-Lern-Dialog öffnen (siehe unten).

### Core-Logik (`wg_manager.py`)

`WireGuardManager` kapselt die gesamte WireGuard-Logik:

- **Config-Liste**: `glob("configs/*.conf")` alphabetisch sortiert. Der Dateiname (ohne `.conf`) wird direkt als Linux-Interface-Name verwendet.
- **State**: `state.json` speichert den aktuellen Index, den Servernamen und den gelernten Button-Code. Fehlt die Datei, wird sie automatisch mit `index=0` angelegt.
- **`wg-quick up/down`**: Läuft via `subprocess.run` mit `timeout=15s`. `"not a wireguard interface"` beim Down-Befehl wird als Erfolg gewertet (war schon down).
- **Tunnel-Verifikation**: `wg show interfaces` prüft nach dem Up-Befehl, ob das Interface wirklich aktiv ist. Fehlt das `wg`-Binary, wird optimistisch `True` zurückgegeben.

### Notifications (`notifier.py`)

Dünner Wrapper um `xbmcgui.Dialog().notification()`. Enthält einen Kodi/Non-Kodi-Guard via `try/except Import` — der Code läuft dadurch auch auf dem Entwicklungsrechner ohne Kodi.

| Funktion | Icon | Dauer |
|---|---|---|
| `connecting(server)` | INFO | 3s |
| `connected(server)` | INFO | 4s |
| `disconnected(server)` | WARNING | 3s |
| `reconnecting(server)` | WARNING | 3s |
| `error(detail)` | ERROR | 5s |

### Fernbedienung einrichten (`button_learner.py` + `keymap_manager.py`)

Kodi hat kein Standard-UI für Button-Mapping. Das Addon implementiert es selbst:

1. Kodi → Addons → WireGuard Switcher → **Konfigurieren**
2. „Remote-Taste belegen" anklicken
3. Ein Vollbild-Dialog erscheint: `ButtonLearnerWindow` (erbt von `xbmcgui.WindowDialog`) fängt den nächsten `onAction`-Event ab
4. `action.getButtonCode()` liefert den gerätespezifischen numerischen Button-Code
5. Der Code wird in `state.json` gespeichert und `keymap_manager` schreibt `keymaps/wireguard.xml` neu:
   ```xml
   <key id="61952">RunScript(service.wireguard.switcher)</key>
   ```
6. `xbmc.executebuiltin("Action(reloadkeymaps)")` lädt die Keymap sofort — kein Kodi-Neustart nötig

Nach einem erneuten Deploy stellt `service.py` beim nächsten Start die Keymap automatisch aus `state.json` wieder her.

---

## State-Datei (`state.json`)

```json
{
  "index": 2,
  "current_server": "HideMe-DE",
  "button_code": 61952
}
```

Wird automatisch verwaltet. Ist gitignored.

---

## WireGuard-Configs (`configs/`)

Standard WireGuard-Config:

```ini
[Interface]
PrivateKey = <private_key_base64>
Address = 10.8.0.2/32
DNS = 185.213.26.187

[Peer]
PublicKey = <server_public_key_base64>
Endpoint = de-frankfurt.hideservers.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

**Wichtige Regeln für Dateinamen:**
- Max. 15 Zeichen (Linux-Interface-Name-Limit)
- Keine Leerzeichen, keine Punkte im Namen
- Nur Buchstaben, Ziffern, Bindestriche
- Beispiele: `HideMe-DE.conf`, `HideMe-NL.conf`, `HideMe-HU.conf`

**Configs niemals committen** — sie enthalten den WireGuard Private Key!

---

## Entwicklung

```bash
# Virtuelle Umgebung aktivieren (Windows)
.venv\Scripts\activate

# Abhängigkeiten installieren
pip install -r requirements.txt
```

`kodistubs` stellt Typ-Stubs für alle Kodi-Module bereit (`xbmc`, `xbmcgui`, `xbmcvfs`, `xbmcaddon`), sodass IDE-Autovervollständigung und Typ-Prüfungen funktionieren. In VS Code den `.venv`-Interpreter auswählen: `Ctrl+Shift+P` → *Python: Select Interpreter*.

---

## Logs auf dem Gerät prüfen

```bash
# WireGuard-Einträge im Kodi-Log
grep -i wireguard /storage/.kodi/temp/kodi.log | tail -20

# Aktive WireGuard-Tunnel
wg show

# Aktueller State
cat /storage/.kodi/addons/service.wireguard.switcher/state.json
```
