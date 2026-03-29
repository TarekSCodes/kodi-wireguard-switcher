# kodi-wireguard-switcher

Kodi-Addon, das WireGuard-VPN-Server per Fernbedienungstaste wechselt und beim Kodi-Start automatisch den zuletzt verwendeten Server wiederherstellt. Enthält einen Kill Switch der alle Verbindungen außer durch den VPN-Tunnel blockiert.

> **Plattform:** Linux erforderlich. Das Addon ruft `wg` und `ip` auf — beides Linux-Kommandozeilentools. Auf Windows-Kodi startet das Addon zwar, der VPN-Wechsel schlägt jedoch fehl, da diese Binaries dort nicht verfügbar sind.

---

## Voraussetzungen

- Kodi auf **Linux** (getestet mit LibreELEC 12 / Kodi 21)
- `wg` unter `/usr/bin/wg` und `ip` unter `/sbin/ip` verfügbar (in LibreELEC 12 nativ vorhanden)
- `iptables` unter `/usr/sbin/iptables` (für Kill Switch, optional)
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
│       ├── wg_manager.py       Core-Logik: WireGuard, State, Config-Cycling, Kill Switch Sync
│       ├── kill_switch.py      iptables Kill Switch (WG_KILL_SWITCH Chain)
│       ├── notifier.py         Kodi-Notification-Wrapper
│       ├── button_learner.py   Dialog zum Erlernen einer Fernbedienungstaste
│       └── keymap_manager.py   Schreibt die Keymap-XML und lädt sie neu
├── configs/                    WireGuard .conf-Dateien (gitignored!)
│   └── README.txt              Regeln für Dateinamen
├── keymaps/
│   └── wireguard.xml           Generierte Keymap (wird zur Laufzeit überschrieben)
├── tests/                      pytest-Tests
├── deploy.py                   SFTP-Deploy-Script (gitignored)
├── requirements.txt            Entwicklungs-Abhängigkeiten
└── .gitignore
```

---

## Funktionsweise

### Beim Kodi-Start (`service.py`)

`service.py` ist als `xbmc.service` registriert und startet automatisch nach dem Login. Es:

1. Stellt die zuletzt konfigurierte Fernbedienungstaste aus `state.json` wieder her (Keymap neu schreiben)
2. Verbindet den zuletzt verwendeten WireGuard-Server (`restore()`)
3. Läuft in einer Schleife und prüft alle 30 Sekunden ob der Tunnel noch aktiv ist — falls nicht, reconnectet er automatisch

`waitForAbort(1)` statt `time.sleep()` sorgt dafür, dass der Service sofort auf ein Kodi-Shutdown-Signal reagiert. Der Tunnel bleibt nach Kodi-Exit aktiv.

### Beim Tastendruck (`switch.py`)

`switch.py` ist als `xbmc.python.script` registriert und wird von der Keymap ausgelöst. Es läuft als eigener kurzlebiger Prozess — ein Absturz killt nicht den Monitor-Service.

Beim Aufruf ohne Argumente: Aktuellen Tunnel trennen → nächste Config in der alphabetisch sortierten Liste aktivieren → in `state.json` speichern.

Beim Aufruf mit Argument `learn`: Button-Lern-Dialog öffnen (siehe unten).

### Core-Logik (`wg_manager.py`)

`WireGuardManager` kapselt die gesamte WireGuard-Logik:

- **Config-Liste**: `glob("configs/*.conf")` alphabetisch sortiert. Der Dateiname (ohne `.conf`) wird direkt als Linux-Interface-Name verwendet (max. 15 Zeichen).
- **State**: `state.json` speichert Index, Servername, Button-Code und die Endpoint-IP. Atomic Write via `tempfile + os.replace()`.
- **WireGuard up**: Kein `wg-quick` (auf LibreELEC nicht verfügbar). Vollständig in Python mit `ip link`, `ip addr`, `ip route` und `wg setconf`. AllowedIPs `0.0.0.0/0` wird in zwei `/1`-Routen aufgeteilt (höhere Priorität als Default-Route, kein Konflikt).
- **Handshake-Warten**: Vor Kill Switch-Aktivierung wird auf einen erfolgreichen WireGuard-Handshake gewartet (max. 8s). Verhindert DNS-Fehler beim Kodi-Start.
- **Tunnel-Erkennung**: `is_tunnel_up()` prüft Interface-Existenz und Handshake-Aktualität. Bei Handshake älter als 3 Minuten (idle Tunnel ohne Traffic) wird ein UDP-Probe gesendet und auf Handshake-Update gewartet — verhindert unnötige Reconnects bei inaktiven Verbindungen.
- **Race Condition Schutz**: `fcntl.flock` verhindert parallele `cycle_next()`-Aufrufe wenn mehrere Tastendruck-Threads gleichzeitig laufen.
-**Failure-Counter**: `auto_reconnect()` zählt aufeinanderfolgende Verbindungsfehler. Nach 3 Fehlern wird automatisch zum nächsten Server gewechselt (wenn mehrere Configs vorhanden).

### Kill Switch (`kill_switch.py`)

Optionaler Schutz, der alle ausgehenden Verbindungen blockiert, die nicht durch den WireGuard-Tunnel laufen.

- Eigene iptables-Chain `WG_KILL_SWITCH` eingehängt in `OUTPUT` und `FORWARD` (nicht INPUT)
- Erlaubt: loopback, WireGuard-Interface, WireGuard-Endpoint UDP:51820, ESTABLISHED/RELATED
- **Leckfreier Reconnect**: Beim Auto-Reconnect bleibt der Kill Switch aktiv — kein 1-2s IP-Leck beim Server-Neuverbinden
- **Atomarer Server-Tausch** (`swap_server()`): Beim Wechsel zu einem neuen Server werden Regeln so getauscht, dass kein Moment existiert, in dem beliebiger Traffic ungefiltert fließen kann

### Notifications (`notifier.py`)

Dünner Wrapper um `xbmcgui.Dialog().notification()`. Enthält einen Kodi/Non-Kodi-Guard via `try/except Import` — der Code läuft dadurch auch auf dem Entwicklungsrechner ohne Kodi.

| Funktion | Icon | Dauer |
|---|---|---|
| `connecting(server)` | INFO | 5s |
| `connected(server)` | INFO | 4s |
| `disconnected(server)` | WARNING | 3s |
| `reconnecting(server)` | WARNING | 3s |
| `error(detail)` | ERROR | 5s |
| `switch_in_progress()` | INFO | 3s |
| `kill_switch_blocking()` | ERROR | 35s |

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

# Tests ausführen
python -m pytest tests/ -v
```

`kodistubs` stellt Typ-Stubs für alle Kodi-Module bereit (`xbmc`, `xbmcgui`, `xbmcvfs`, `xbmcaddon`), sodass IDE-Autovervollständigung und Typ-Prüfungen funktionieren. In VS Code den `.venv`-Interpreter auswählen: `Ctrl+Shift+P` → *Python: Select Interpreter*.

---

## Logs auf dem Gerät prüfen

```bash
# WireGuard-Einträge im Kodi-Log
grep -i wireguard /storage/.kodi/temp/kodi.log | tail -30

# Aktive WireGuard-Tunnel
wg show

# iptables Kill Switch Status
iptables -L WG_KILL_SWITCH -v 2>/dev/null || echo "Kill Switch inaktiv"

# Aktueller State
cat /storage/.kodi/addons/service.wireguard.switcher/state.json
```
