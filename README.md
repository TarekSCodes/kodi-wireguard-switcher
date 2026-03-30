# kodi-wireguard-switcher

Kodi addon that switches WireGuard VPN servers via a remote button and automatically restores the last used server on Kodi startup. Includes a Kill Switch that blocks all connections except through the VPN tunnel.

> **Platform:** Linux required. The addon calls `wg` and `ip` — both Linux command-line tools. On Windows Kodi the addon starts, but VPN switching fails because these binaries are not available there.

---

## Requirements

- Kodi on **Linux** (tested with LibreELEC 12 / Kodi 21)
- `wg` at `/usr/bin/wg` and `ip` at `/sbin/ip` (natively available in LibreELEC 12)
- `iptables` at `/usr/sbin/iptables` (for Kill Switch, optional)
- WireGuard configs from VPN provider (tested with HideMe)
- Python 3 on the development machine

---

## Project Structure

```
service.wireguard.switcher/
├── addon.xml                   Kodi addon manifest
├── service.py                  Background service (starts with Kodi)
├── switch.py                   Script for button press (VPN switch)
├── resources/
│   ├── settings.xml            Addon settings in Kodi
│   └── lib/
│       ├── wg_manager.py       Core logic: WireGuard, state, config cycling, Kill Switch sync
│       ├── kill_switch.py      iptables Kill Switch (WG_KILL_SWITCH chain)
│       ├── notifier.py         Kodi notification wrapper
│       ├── button_learner.py   Dialog for learning a remote button
│       └── keymap_manager.py   Writes the keymap XML and reloads it
├── configs/                    WireGuard .conf files (gitignored!)
│   └── README.txt              File naming rules
├── keymaps/
│   └── wireguard.xml           Generated keymap (overwritten at runtime)
├── tests/                      pytest tests
├── deploy.py                   SFTP deploy script (gitignored)
├── requirements.txt            Development dependencies
└── .gitignore
```

---

## How It Works

### On Kodi Startup (`service.py`)

`service.py` is registered as an `xbmc.service` and starts automatically after login. It:

1. Restores the last configured remote button from `state.json` (rewrites keymap)
2. Connects to the last used WireGuard server (`restore()`)
3. Runs in a loop and checks every 30 seconds whether the tunnel is still active — if not, it reconnects automatically

`waitForAbort(1)` instead of `time.sleep()` ensures the service responds immediately to a Kodi shutdown signal. The tunnel stays active after Kodi exits.

### On Button Press (`switch.py`)

`switch.py` is registered as `xbmc.python.script` and triggered by the keymap. It runs as its own short-lived process — a crash does not kill the monitor service.

Called without arguments: disconnect the current tunnel → activate the next config in the alphabetically sorted list → save to `state.json`.

Called with argument `learn`: open the button learning dialog (see below).

### Core Logic (`wg_manager.py`)

`WireGuardManager` encapsulates all WireGuard logic:

- **Config list**: `glob("configs/*.conf")` sorted alphabetically. The filename (without `.conf`) is used directly as the Linux interface name (max. 15 characters).
- **State**: `state.json` stores index, server name, button code, and endpoint IP. Atomic write via `tempfile + os.replace()`.
- **WireGuard up**: No `wg-quick` (not available on LibreELEC). Fully implemented in Python with `ip link`, `ip addr`, `ip route`, and `wg setconf`. AllowedIPs `0.0.0.0/0` is split into two `/1` routes (higher priority than the default route, no conflicts).
- **Handshake wait**: Before activating the Kill Switch, a successful WireGuard handshake is awaited (max. 8s). Prevents DNS errors on Kodi startup.
- **Tunnel detection**: `is_tunnel_up()` checks interface existence and handshake freshness. If the handshake is older than 3 minutes (idle tunnel without traffic), a UDP probe is sent and the system waits for a handshake update — prevents unnecessary reconnects for idle connections.
- **Race condition protection**: `fcntl.flock` prevents parallel `cycle_next()` calls when multiple button-press threads run simultaneously.
- **Failure counter**: `auto_reconnect()` counts consecutive connection failures. After 3 failures it automatically switches to the next server (when multiple configs are available).

### Kill Switch (`kill_switch.py`)

Optional protection that blocks all outgoing connections not going through the WireGuard tunnel.

- Dedicated iptables chain `WG_KILL_SWITCH` inserted into `OUTPUT` and `FORWARD` (not INPUT)
- Allows: loopback, WireGuard interface, WireGuard endpoint UDP:51820, ESTABLISHED/RELATED
- **Leak-free reconnect**: During auto-reconnect the Kill Switch stays active — no 1-2s IP leak when reconnecting to a server
- **Atomic server swap** (`swap_server()`): When switching to a new server, rules are swapped so there is no moment where arbitrary traffic can flow unfiltered

### Notifications (`notifier.py`)

Thin wrapper around `xbmcgui.Dialog().notification()`. Contains a Kodi/non-Kodi guard via `try/except import` — the code also runs on the development machine without Kodi.

| Function | Icon | Duration |
|---|---|---|
| `connecting(server)` | INFO | 5s |
| `connected(server)` | INFO | 4s |
| `disconnected(server)` | WARNING | 3s |
| `reconnecting(server)` | WARNING | 3s |
| `error(detail)` | ERROR | 5s |
| `switch_in_progress()` | INFO | 3s |
| `kill_switch_blocking()` | ERROR | 35s |

### Remote Button Setup (`button_learner.py` + `keymap_manager.py`)

Kodi has no standard UI for button mapping. The addon implements it itself:

1. Kodi → Addons → WireGuard Switcher → **Configure**
2. Click "Map remote button"
3. A full-screen dialog appears: `ButtonLearnerWindow` (inherits from `xbmcgui.WindowDialog`) captures the next `onAction` event
4. `action.getButtonCode()` returns the device-specific numeric button code
5. The code is saved to `state.json` and `keymap_manager` rewrites `keymaps/wireguard.xml`:
   ```xml
   <key id="61952">RunScript(service.wireguard.switcher)</key>
   ```
6. `xbmc.executebuiltin("Action(reloadkeymaps)")` reloads the keymap immediately — no Kodi restart required

After a fresh deploy, `service.py` automatically restores the keymap from `state.json` on next startup.

---

## State File (`state.json`)

```json
{
  "index": 2,
  "current_server": "HideMe-DE",
  "button_code": 61952
}
```

Managed automatically. Gitignored.

---

## WireGuard Configs (`configs/`)

Standard WireGuard config:

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

**Important filename rules:**
- Max. 15 characters (Linux interface name limit)
- No spaces, no dots in the name
- Letters, digits, and hyphens only
- Examples: `HideMe-DE.conf`, `HideMe-NL.conf`, `HideMe-HU.conf`

**Never commit configs** — they contain the WireGuard private key!

---

## Development

```bash
# Activate virtual environment (Windows)
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v
```

`kodistubs` provides type stubs for all Kodi modules (`xbmc`, `xbmcgui`, `xbmcvfs`, `xbmcaddon`), enabling IDE autocompletion and type checking. In VS Code select the `.venv` interpreter: `Ctrl+Shift+P` → *Python: Select Interpreter*.

---

## Checking Logs on the Device

```bash
# WireGuard entries in the Kodi log
grep -i wireguard /storage/.kodi/temp/kodi.log | tail -30

# Active WireGuard tunnels
wg show

# iptables Kill Switch status
iptables -L WG_KILL_SWITCH -v 2>/dev/null || echo "Kill Switch inactive"

# Current state
cat /storage/.kodi/addons/service.wireguard.switcher/state.json
```
