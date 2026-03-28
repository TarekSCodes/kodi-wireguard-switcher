import glob
import json
import os
import re
import socket
import subprocess
import tempfile

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
            with open(self._state_file, "w") as f:
                json.dump(self._state, f, indent=2)
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

            # 3. IP-Adresse setzen
            if address:
                rc, _, err = self._run([IP_BIN, "addr", "add", address, "dev", iface])
                if rc != 0 and "exists" not in err.lower():
                    notifier._log_msg("warning", f"ip addr add: {err[:40]}")

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

            # 8. Kill Switch aktivieren (nach erfolgreichem Tunnel-Aufbau)
            if self._kill_switch_enabled():
                kill_switch.enable(iface, endpoint_ip or "")

        finally:
            try:
                os.unlink(stripped)
            except OSError:
                pass

        return True, ""

    def _wg_down(self, conf_path: str) -> tuple:
        """
        Trennt einen WireGuard-Tunnel.
        Entspricht funktional: wg-quick down <conf>
        """
        iface = self._config_name(conf_path)

        # Kill Switch IMMER deaktivieren — auch wenn Interface schon down ist.
        # Verhindert stale iptables-Regeln die den Pi sperren.
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

    def is_tunnel_up(self) -> bool:
        conf_path = self._current_config_path()
        if not conf_path:
            return False
        return self._verify_tunnel(self._config_name(conf_path))

    def auto_reconnect(self):
        if not self._configs:
            return
        if not self.is_tunnel_up():
            conf_path = self._current_config_path()
            server_name = self._config_name(conf_path)
            notifier.reconnecting(server_name)
            self._bring_down_if_up(conf_path)
            ok, err = self._wg_up(conf_path)
            if not ok:
                if self._kill_switch_enabled():
                    # Kill Switch aktiv + Reconnect fehlgeschlagen → Internet blockiert.
                    # Persistente Notification (35s) damit User es sieht und versteht.
                    notifier.kill_switch_blocking()
                else:
                    notifier.error(f"Reconnect failed — {server_name}: {err}")
