try:
    import fcntl as _fcntl
    _HAVE_FCNTL = True
except ImportError:
    _HAVE_FCNTL = False  # Windows — kein Locking (LibreELEC/Linux ist Zielplattform)
import glob
import json
import os
import re
import socket
import subprocess
import tempfile
import time

import xbmcaddon

from resources.lib import kill_switch
from resources.lib import notifier

WG_BIN = "/usr/bin/wg"
RESOLV_CONF = "/etc/resolv.conf"

def _find_ip_bin() -> str:
    for path in ("/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"):
        if os.path.isfile(path):
            return path
    return "/sbin/ip"  # Fallback — Fehlermeldung kommt dann von _check_requirements

IP_BIN = _find_ip_bin()

# Interface-Felder die wg setconf NICHT akzeptiert — müssen herausgefiltert werden
_IFACE_STRIP = {"address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown"}


class WireGuardManager:
    def __init__(self, addon_path: str):
        self._configs_dir = os.path.join(addon_path, "configs")
        self._state_file = os.path.join(addon_path, "state.json")
        self._configs = []
        self._state = {}
        self._reconnect_failures = 0
        self._load_configs()
        self._load_state()

    # ------------------------------------------------------------------ #
    # Config-Parsing                                                       #
    # ------------------------------------------------------------------ #

    def _parse_wg_conf(self, conf_path: str) -> dict:
        """
        Parst eine WireGuard .conf-Datei.
        Gibt zurück: {'interface': {key: value}, 'peers': [{key: value}, ...]}
        """
        result = {"interface": {}, "peers": []}
        section = None
        current_peer = {}

        with open(conf_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line == "[Interface]":
                    section = "interface"
                elif line == "[Peer]":
                    if section == "peer" and current_peer:
                        result["peers"].append(current_peer)
                    current_peer = {}
                    section = "peer"
                elif "=" in line:
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip()
                    if section == "interface":
                        result["interface"][key] = value
                    elif section == "peer":
                        current_peer[key] = value

        if section == "peer" and current_peer:
            result["peers"].append(current_peer)

        return result

    def _write_stripped_conf(self, conf_data: dict) -> str:
        """
        Schreibt eine temporäre Stripped-Config-Datei für 'wg setconf'
        (ohne Address, DNS etc.). Gibt den Pfad zurück — Aufrufer muss löschen.
        """
        lines = ["[Interface]"]
        for key, value in conf_data["interface"].items():
            if key.lower() not in _IFACE_STRIP:
                lines.append(f"{key} = {value}")
        for peer in conf_data["peers"]:
            lines.append("[Peer]")
            for key, value in peer.items():
                lines.append(f"{key} = {value}")

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        tmp.write("\n".join(lines) + "\n")
        tmp.close()
        return tmp.name

    # ------------------------------------------------------------------ #
    # State                                                                #
    # ------------------------------------------------------------------ #

    def _load_configs(self):
        pattern = os.path.join(self._configs_dir, "*.conf")
        self._configs = sorted(glob.glob(pattern))
        notifier._log_msg("info", f"Found configs: {[self._config_name(c) for c in self._configs]}")

    def _config_name(self, path: str) -> str:
        return os.path.splitext(os.path.basename(path))[0]

    def _load_state(self):
        try:
            with open(self._state_file, "r") as f:
                self._state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._state = {"index": 0, "current_server": ""}
            self._save_state()
            return
        if self._configs and self._state.get("index", 0) >= len(self._configs):
            self._state["index"] = 0
            self._save_state()

    def _save_state(self):
        idx = self._state.get("index", 0)
        server = self._config_name(self._configs[idx]) if self._configs else ""
        self._state["index"] = idx
        self._state["current_server"] = server
        try:
            dir_ = os.path.dirname(self._state_file)
            fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self._state, f, indent=2)
                os.replace(tmp_path, self._state_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as e:
            notifier._log_msg("error", f"Could not write state.json: {e}")

    def set_button_code(self, code: int):
        self._state["button_code"] = code
        self._save_state()

    def get_state(self) -> dict:
        return self._state

    def _current_config_path(self) -> str:
        idx = self._state.get("index", 0)
        if not self._configs:
            return ""
        if idx >= len(self._configs):
            idx = 0
        return self._configs[idx]

    # ------------------------------------------------------------------ #
    # Netzwerk-Hilfsmethoden                                               #
    # ------------------------------------------------------------------ #

    def _run(self, cmd: list) -> tuple:
        """Führt einen Systembefehl aus. Gibt (returncode, stdout, stderr) zurück."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timed out"
        except FileNotFoundError:
            return -1, "", f"{cmd[0]}: not found"

    def _kill_switch_enabled(self) -> bool:
        try:
            return xbmcaddon.Addon().getSetting("kill_switch") == "true"
        except Exception:
            return False

    def _check_requirements(self) -> bool:
        for binary in (WG_BIN, IP_BIN):
            if not os.path.isfile(binary):
                notifier.error(f"Required binary not found: {binary}")
                return False
        if self._kill_switch_enabled() and not kill_switch.is_available():
            notifier.error("Kill Switch aktiv, aber iptables fehlt — VPN-Start abgebrochen")
            return False
        return True

    def _get_default_gateway(self) -> tuple:
        """Gibt (gateway_ip, interface) der aktuellen Default-Route zurück."""
        rc, out, _ = self._run([IP_BIN, "route", "show", "default"])
        if rc != 0:
            return None, None
        match = re.search(r"via\s+(\S+)\s+dev\s+(\S+)", out)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def _resolve_endpoint_ip(self, endpoint: str) -> str | None:
        """Löst 'hostname:port' in eine IP-Adresse auf."""
        try:
            host, _, port = endpoint.rpartition(":")
            infos = socket.getaddrinfo(host, int(port), socket.AF_INET)
            if infos:
                return infos[0][4][0]
        except Exception:
            pass
        return None

    def _save_dns(self):
        """Sichert /etc/resolv.conf in state.json."""
        try:
            with open(RESOLV_CONF, "r") as f:
                self._state["_saved_dns"] = f.read()
            self._save_state()
        except OSError:
            pass

    def _write_dns(self, dns_value: str):
        """Schreibt VPN-DNS-Server in /etc/resolv.conf."""
        servers = [s.strip() for s in dns_value.split(",")]
        content = "\n".join(f"nameserver {s}" for s in servers) + "\n"
        try:
            with open(RESOLV_CONF, "w") as f:
                f.write(content)
        except OSError as e:
            notifier._log_msg("warning", f"Could not set DNS: {e}")

    def _restore_dns(self):
        """Stellt /etc/resolv.conf aus dem gesicherten State wieder her."""
        saved = self._state.pop("_saved_dns", None)
        if saved:
            try:
                with open(RESOLV_CONF, "w") as f:
                    f.write(saved)
                self._save_state()
            except OSError as e:
                notifier._log_msg("warning", f"Could not restore DNS: {e}")

    # ------------------------------------------------------------------ #
    # Tunnel Up / Down                                                     #
    # ------------------------------------------------------------------ #

    def _wg_up(self, conf_path: str) -> tuple:
        """
        Bringt einen WireGuard-Tunnel hoch.
        Entspricht funktional: wg-quick up <conf>
        """
        iface = self._config_name(conf_path)

        try:
            conf = self._parse_wg_conf(conf_path)
        except OSError as e:
            return False, f"Cannot read config: {e}"

        iface_conf = conf["interface"]
        address = iface_conf.get("Address", "")
        dns = iface_conf.get("DNS", "")
        mtu = iface_conf.get("MTU", "1420")

        # AllowedIPs und Endpoint aus allen Peers sammeln
        allowed_ips = []
        endpoint = None
        for peer in conf["peers"]:
            for cidr in peer.get("AllowedIPs", "").split(","):
                cidr = cidr.strip()
                if cidr:
                    allowed_ips.append(cidr)
            if not endpoint and "Endpoint" in peer:
                endpoint = peer["Endpoint"]

        # Aktuellen Default-Gateway ermitteln (für Endpoint-Route)
        gw_ip, _ = self._get_default_gateway()

        # Endpoint-IP auflösen (verhindert Routing-Loop durch den eigenen Tunnel)
        endpoint_ip = None
        if endpoint and gw_ip:
            endpoint_ip = self._resolve_endpoint_ip(endpoint)
            if endpoint_ip:
                self._state["_endpoint_ip"] = endpoint_ip
        # Fallback: gecachte IP nutzen wenn DNS fehlschlägt
        # (Kill Switch blockiert DNS-Queries zum Router während Reconnect)
        if not endpoint_ip:
            endpoint_ip = self._state.get("_endpoint_ip")

        # Stripped Config für wg setconf schreiben
        stripped = self._write_stripped_conf(conf)
        try:
            # 1. Interface anlegen
            rc, _, err = self._run([IP_BIN, "link", "add", iface, "type", "wireguard"])
            if rc != 0 and "exists" not in err.lower():
                return False, f"ip link add: {err[:60]}"

            # 2. WireGuard konfigurieren
            rc, _, err = self._run([WG_BIN, "setconf", iface, stripped])
            if rc != 0:
                self._run([IP_BIN, "link", "del", iface])
                return False, f"wg setconf: {err[:60]}"

            # 3. IP-Adresse(n) setzen (kann komma-separiert sein: "10.x/32, fd00::x/128")
            for addr in address.split(","):
                addr = addr.strip()
                if not addr:
                    continue
                rc, _, err = self._run([IP_BIN, "addr", "add", addr, "dev", iface])
                if rc != 0 and "exists" not in err.lower():
                    notifier._log_msg("warning", f"ip addr add {addr}: {err[:60]}")

            # 4. MTU setzen und Interface hochbringen
            self._run([IP_BIN, "link", "set", "mtu", mtu, "up", "dev", iface])

            # 5. Endpoint-spezifische Route via ursprünglichem Gateway
            if endpoint_ip and gw_ip:
                self._run([IP_BIN, "route", "add", f"{endpoint_ip}/32", "via", gw_ip])

            # 6. Routen für AllowedIPs
            for cidr in allowed_ips:
                if cidr == "0.0.0.0/0":
                    # In zwei /1-Routen aufteilen — höhere Spezifität als Default-Route,
                    # verhindert Konflikte mit bestehender Default-Route
                    self._run([IP_BIN, "route", "add", "0.0.0.0/1", "dev", iface])
                    self._run([IP_BIN, "route", "add", "128.0.0.0/1", "dev", iface])
                elif cidr == "::/0":
                    self._run([IP_BIN, "-6", "route", "add", "::/1", "dev", iface])
                    self._run([IP_BIN, "-6", "route", "add", "8000::/1", "dev", iface])
                else:
                    self._run([IP_BIN, "route", "add", cidr, "dev", iface])

            # 7. DNS setzen (resolv.conf vorher sichern)
            if dns:
                self._save_dns()
                self._write_dns(dns)

            # 8. Auf WireGuard-Handshake warten — stellt sicher dass der Tunnel
            #    tatsächlich funktioniert bevor "Connected" signalisiert wird
            self._wait_for_handshake(iface)

            # 9. Kill Switch aktivieren
            if self._kill_switch_enabled():
                kill_switch.enable(iface, endpoint_ip or "")

        finally:
            try:
                os.unlink(stripped)
            except OSError:
                pass

        return True, ""

    def _wg_down(self, conf_path: str, disable_kill_switch: bool = True) -> tuple:
        """
        Trennt einen WireGuard-Tunnel.
        Entspricht funktional: wg-quick down <conf>
        disable_kill_switch=False: Kill Switch bleibt aktiv (für leckfreien Reconnect).
        """
        iface = self._config_name(conf_path)

        # Kill Switch deaktivieren (Default) — verhindert stale iptables-Regeln.
        # Bei disable_kill_switch=False bleibt er aktiv (Reconnect zum gleichen Server).
        if disable_kill_switch:
            kill_switch.disable()

        # Prüfen ob Interface überhaupt existiert
        rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
        if rc == 0 and iface not in out.split():
            return True, ""  # War schon down

        # DNS wiederherstellen
        self._restore_dns()

        # Endpoint-Route entfernen (liegt auf physischem Interface, nicht auf wg-Interface)
        endpoint_ip = self._state.pop("_endpoint_ip", None)
        if endpoint_ip:
            self._run([IP_BIN, "route", "del", f"{endpoint_ip}/32"])
            self._save_state()

        # Interface löschen (entfernt automatisch alle zugehörigen Routen)
        rc, _, err = self._run([IP_BIN, "link", "del", iface])
        if rc != 0:
            combined = err.lower()
            if "not found" in combined or "does not exist" in combined:
                return True, ""
            return False, f"ip link del: {err[:60]}"

        return True, ""

    def _bring_down_if_up(self, conf_path: str):
        """Best-effort: Tunnel trennen, Fehler ignorieren."""
        if conf_path:
            self._wg_down(conf_path)

    def _verify_tunnel(self, interface_name: str) -> bool:
        """Prüft ob das WireGuard-Interface aktiv ist."""
        try:
            rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
            if rc != 0:
                return True  # wg nicht verfügbar → optimistisch
            return interface_name in out.strip().split()
        except Exception:
            return True

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def restore(self):
        if not self._configs:
            notifier.error("No .conf files found in configs/")
            return
        if not self._check_requirements():
            return

        conf_path = self._current_config_path()
        server_name = self._config_name(conf_path)
        notifier.connecting(server_name)
        self._bring_down_if_up(conf_path)
        ok, err = self._wg_up(conf_path)
        if not ok:
            if self._kill_switch_enabled():
                notifier.kill_switch_blocking()
            else:
                notifier.error(f"{server_name}: {err}")
            return
        if self._verify_tunnel(server_name):
            notifier.connected(server_name)
        else:
            if self._kill_switch_enabled():
                notifier.kill_switch_blocking()
            else:
                notifier.error(f"{server_name}: tunnel not visible after up")

    def cycle_next(self):
        if not self._configs:
            notifier.error("No .conf files found in configs/")
            return
        if not self._check_requirements():
            return

        acquired, lock_file = self._acquire_switch_lock()
        if not acquired:
            notifier._log_msg("warning", "cycle_next: Switch bereits im Gange — ignoriert")
            notifier.switch_in_progress()
            return
        try:
            current_conf = self._current_config_path()
            current_server = self._config_name(current_conf) if current_conf else ""
            self._bring_down_if_up(current_conf)
            if current_server:
                notifier.disconnected(current_server)

            current_idx = self._state.get("index", 0)
            next_idx = (current_idx + 1) % len(self._configs)
            self._state["index"] = next_idx
            self._save_state()

            new_conf = self._current_config_path()
            new_server = self._config_name(new_conf)
            notifier.connecting(new_server)
            ok, err = self._wg_up(new_conf)
            if not ok:
                notifier.error(f"{new_server}: {err}")
                return
            if self._verify_tunnel(new_server):
                notifier.connected(new_server)
            else:
                notifier.error(f"{new_server}: tunnel not visible after up")
        finally:
            self._release_switch_lock(lock_file)

    def is_tunnel_up(self) -> bool:
        """
        Prüft ob der WireGuard-Tunnel aktiv und funktionsfähig ist.
        Kriterien: Interface muss existieren UND Handshake wurde erfolgreich abgeschlossen.
        Bei altem Handshake (idle Tunnel > 3 min ohne Traffic): Probe senden und warten
        ob WireGuard einen neuen Handshake initiiert — unterscheidet idle von server-down.
        """
        conf_path = self._current_config_path()
        if not conf_path:
            return False
        iface = self._config_name(conf_path)

        # 1. Interface muss existieren
        rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
        if rc != 0:
            return True  # wg nicht verfügbar → optimistisch
        if iface not in out.strip().split():
            return False

        # 2. Handshake-Timestamp prüfen
        rc, out, _ = self._run([WG_BIN, "show", iface, "latest-handshakes"])
        if rc != 0:
            return True  # Fallback optimistisch

        ts = 0
        for line in out.strip().splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    ts = int(parts[-1])
                    break
                except ValueError:
                    pass

        if ts == 0:
            return False  # Noch kein Handshake abgeschlossen

        if (time.time() - ts) < 180:
            return True  # Frischer Handshake → Tunnel definitiv aktiv

        # Handshake > 3 min alt: könnte idle sein (kein Traffic → kein Rekey)
        # oder Server ist ausgefallen. Probe senden und kurz warten.
        return self._probe_handshake(iface, ts)

    def _probe_handshake(self, iface: str, old_ts: int) -> bool:
        """
        Sendet ein UDP-Paket um WireGuard-Handshake zu triggern.
        Gibt True zurück wenn der Handshake-Timestamp sich innerhalb von 3s aktualisiert
        (Tunnel war nur idle), False wenn kein Update erfolgt (Server wahrscheinlich down).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.connect(("8.8.8.8", 53))
            sock.send(b"\x00")
            sock.close()
        except Exception:
            pass

        deadline = time.time() + 6.0
        while time.time() < deadline:
            time.sleep(0.3)
            rc, out, _ = self._run([WG_BIN, "show", iface, "latest-handshakes"])
            if rc == 0:
                for line in out.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            if int(parts[-1]) > old_ts:
                                return True  # Handshake erneuert → Server erreichbar
                        except ValueError:
                            pass

        notifier._log_msg("warning", f"is_tunnel_up: kein Handshake-Update nach Probe ({iface})")
        return False

    def _wait_for_handshake(self, iface: str, timeout: float = 8.0) -> bool:
        """
        Wartet bis WireGuard einen NEUEN Handshake abgeschlossen hat.
        Liest zuerst den Baseline-Timestamp — gibt True erst zurück wenn ein
        NEUERER Timestamp erscheint. Verhindert False-Positive bei gestaletem
        Handshake aus einer früheren Session (z.B. Interface existiert noch).
        """
        # Baseline-Timestamp einlesen (0 wenn Interface frisch oder noch kein Handshake)
        baseline_ts = 0
        rc, out, _ = self._run([WG_BIN, "show", iface, "latest-handshakes"])
        if rc == 0:
            for line in out.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        baseline_ts = int(parts[-1])
                        break
                    except ValueError:
                        pass

        # UDP-Paket senden — wird via 0.0.0.0/1-Route durch WireGuard geroutet
        # und triggert die Handshake-Initiation im WireGuard-Kernel-Modul
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.connect(("8.8.8.8", 53))
            sock.send(b"\x00")
            sock.close()
        except Exception:
            pass

        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, out, _ = self._run([WG_BIN, "show", iface, "latest-handshakes"])
            if rc == 0:
                for line in out.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            ts = int(parts[-1])
                            if ts > baseline_ts:
                                notifier._log_msg("info", f"WireGuard Handshake abgeschlossen ({iface})")
                                return True
                        except ValueError:
                            pass
            time.sleep(0.3)

        notifier._log_msg("warning", f"WireGuard Handshake Timeout nach {timeout}s ({iface}) — fortfahren")
        return False

    def _acquire_switch_lock(self):
        """Non-blocking exclusive lock. Gibt (True, file) oder (False, None) zurück.
        Auf Nicht-Linux-Plattformen (kein fcntl): immer erfolgreich (no-op)."""
        if not _HAVE_FCNTL:
            return True, None
        lock_path = os.path.join(os.path.dirname(self._state_file), "switch.lock")
        lf = open(lock_path, "w")
        try:
            _fcntl.flock(lf.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return True, lf
        except (IOError, OSError):
            lf.close()
            return False, None

    def _release_switch_lock(self, lock_file):
        if lock_file and _HAVE_FCNTL:
            try:
                _fcntl.flock(lock_file.fileno(), _fcntl.LOCK_UN)
                lock_file.close()
            except Exception:
                pass

    def _sync_kill_switch(self):
        """
        Synchronisiert iptables-Regeln mit dem aktuellen Kill-Switch-Setting.
        - Setting=True, iptables=aus, Tunnel oben  → aktivieren
        - Setting=False, iptables=an               → sofort deaktivieren
        """
        ks_setting = self._kill_switch_enabled()
        ks_active = kill_switch.is_enabled()

        if ks_setting and not ks_active and self.is_tunnel_up():
            iface = self._config_name(self._current_config_path())
            endpoint_ip = self._state.get("_endpoint_ip", "")
            kill_switch.enable(iface, endpoint_ip)
            notifier._log_msg("info", "Kill Switch sync: aktiviert (Setting=an, Tunnel oben)")
        elif not ks_setting and ks_active:
            kill_switch.disable()
            notifier._log_msg("info", "Kill Switch sync: deaktiviert (Setting=aus)")

    def auto_reconnect(self):
        if not self._configs:
            return
        acquired, lock_file = self._acquire_switch_lock()
        if not acquired:
            notifier._log_msg("info", "auto_reconnect: Switch im Gange — übersprungen")
            return
        try:
            self._load_state()  # State nachladen — switch.py kann Index geändert haben
            if not self.is_tunnel_up():
                conf_path = self._current_config_path()
                server_name = self._config_name(conf_path)
                ks_was_active = kill_switch.is_enabled()
                old_endpoint = self._state.get("_endpoint_ip", "")  # VOR _wg_down sichern!
                notifier.reconnecting(server_name)

                # Kill Switch erhalten wenn möglich — kein IP-Leck bei Reconnect
                self._wg_down(conf_path, disable_kill_switch=not ks_was_active)
                # Endpoint-IP als Fallback wiederherstellen — _wg_down() entfernt sie
                # aus State, aber _wg_up() braucht sie wenn Kill Switch DNS blockiert
                if old_endpoint:
                    self._state["_endpoint_ip"] = old_endpoint
                ok, err = self._wg_up(conf_path)

                if ok and self._verify_tunnel(server_name):
                    self._reconnect_failures = 0
                    notifier.connected(server_name)
                else:
                    self._reconnect_failures += 1
                    notifier._log_msg("warning",
                        f"Reconnect fehlgeschlagen ({server_name}), Versuch {self._reconnect_failures}")

                    if self._reconnect_failures >= 3 and len(self._configs) > 1:
                        # Server dauerhaft ausgefallen → zum nächsten wechseln
                        current_idx = self._state.get("index", 0)
                        next_idx = (current_idx + 1) % len(self._configs)
                        next_conf = self._configs[next_idx]
                        next_server = self._config_name(next_conf)
                        notifier._log_msg("warning",
                            f"Server {server_name} dauerhaft ausgefallen — wechsle zu {next_server}")

                        self._state["index"] = next_idx
                        self._save_state()
                        self._reconnect_failures = 0

                        # Neuen Tunnel aufbauen (Kill Switch noch aktiv mit alten Regeln)
                        ok2, _ = self._wg_up(next_conf)
                        new_endpoint = self._state.get("_endpoint_ip", "")
                        if ok2 and ks_was_active:
                            # Atomarer Regelaustausch: old_iface→new_iface, kein Leck
                            kill_switch.swap_server(next_server, new_endpoint,
                                                    server_name, old_endpoint)
                        elif not ok2:
                            notifier.error(f"Auto-Cycle fehlgeschlagen: {next_server}")
                    elif self._kill_switch_enabled():
                        notifier.kill_switch_blocking()
                    else:
                        notifier.error(f"Reconnect failed — {server_name}: {err}")
            self._sync_kill_switch()
        finally:
            self._release_switch_lock(lock_file)
