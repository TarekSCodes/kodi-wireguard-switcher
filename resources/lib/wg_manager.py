try:
    import fcntl as _fcntl
    _HAVE_FCNTL = True
except ImportError:
    _HAVE_FCNTL = False  # Windows — no locking (LibreELEC/Linux is the target platform)
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
    return "/sbin/ip"  # Fallback — error will come from _check_requirements

IP_BIN = _find_ip_bin()

# Interface fields that wg setconf does NOT accept — must be filtered out
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
    # Config Parsing                                                       #
    # ------------------------------------------------------------------ #

    def _parse_wg_conf(self, conf_path: str) -> dict:
        """
        Parses a WireGuard .conf file.
        Returns: {'interface': {key: value}, 'peers': [{key: value}, ...]}
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
        Writes a temporary stripped config file for 'wg setconf'
        (without Address, DNS, etc.). Returns the path — caller must delete.
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
    # Network Helpers                                                      #
    # ------------------------------------------------------------------ #

    def _run(self, cmd: list) -> tuple:
        """Runs a system command. Returns (returncode, stdout, stderr)."""
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
            notifier.error("Kill Switch enabled but iptables missing — VPN start aborted")
            return False
        return True

    def _get_default_gateway(self) -> tuple:
        """Returns (gateway_ip, interface) of the current default route."""
        rc, out, _ = self._run([IP_BIN, "route", "show", "default"])
        if rc != 0:
            return None, None
        match = re.search(r"via\s+(\S+)\s+dev\s+(\S+)", out)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def _resolve_endpoint_ip(self, endpoint: str) -> str | None:
        """Resolves 'hostname:port' to an IP address."""
        try:
            host, _, port = endpoint.rpartition(":")
            infos = socket.getaddrinfo(host, int(port), socket.AF_INET)
            if infos:
                return infos[0][4][0]
        except Exception:
            pass
        return None

    def _save_dns(self):
        """Backs up /etc/resolv.conf into state.json."""
        try:
            with open(RESOLV_CONF, "r") as f:
                self._state["_saved_dns"] = f.read()
            self._save_state()
        except OSError:
            pass

    def _write_dns(self, dns_value: str):
        """Writes VPN DNS servers into /etc/resolv.conf."""
        servers = [s.strip() for s in dns_value.split(",")]
        content = "\n".join(f"nameserver {s}" for s in servers) + "\n"
        try:
            with open(RESOLV_CONF, "w") as f:
                f.write(content)
        except OSError as e:
            notifier._log_msg("warning", f"Could not set DNS: {e}")

    def _restore_dns(self):
        """Restores /etc/resolv.conf from the saved state."""
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
        Brings up a WireGuard tunnel.
        Functionally equivalent to: wg-quick up <conf>
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

        # Collect AllowedIPs and Endpoint from all peers
        allowed_ips = []
        endpoint = None
        for peer in conf["peers"]:
            for cidr in peer.get("AllowedIPs", "").split(","):
                cidr = cidr.strip()
                if cidr:
                    allowed_ips.append(cidr)
            if not endpoint and "Endpoint" in peer:
                endpoint = peer["Endpoint"]

        # Get current default gateway (for endpoint route)
        gw_ip, _ = self._get_default_gateway()

        # Read endpoint port from config (e.g. HideMe uses port 428, not 51820)
        endpoint_port = 51820
        if endpoint:
            try:
                endpoint_port = int(endpoint.rpartition(":")[2])
            except (ValueError, IndexError):
                pass

        # Resolve endpoint IP (prevents routing loop through our own tunnel)
        endpoint_ip = None
        if endpoint and gw_ip:
            endpoint_ip = self._resolve_endpoint_ip(endpoint)
            if endpoint_ip:
                self._state["_endpoint_ip"] = endpoint_ip
                self._state["_endpoint_port"] = endpoint_port
        # Fallback: use cached IP/port if DNS fails
        # (Kill Switch blocks DNS queries to the router during reconnect)
        if not endpoint_ip:
            endpoint_ip = self._state.get("_endpoint_ip")
            endpoint_port = self._state.get("_endpoint_port", endpoint_port)

        # Write stripped config for wg setconf
        stripped = self._write_stripped_conf(conf)
        try:
            # 1. Create interface
            rc, _, err = self._run([IP_BIN, "link", "add", iface, "type", "wireguard"])
            if rc != 0 and "exists" not in err.lower():
                return False, f"ip link add: {err[:60]}"

            # 2. Configure WireGuard
            rc, _, err = self._run([WG_BIN, "setconf", iface, stripped])
            if rc != 0:
                self._run([IP_BIN, "link", "del", iface])
                return False, f"wg setconf: {err[:60]}"

            # 3. Set IP address(es) (may be comma-separated: "10.x/32, fd00::x/128")
            for addr in address.split(","):
                addr = addr.strip()
                if not addr:
                    continue
                rc, _, err = self._run([IP_BIN, "addr", "add", addr, "dev", iface])
                if rc != 0 and "exists" not in err.lower():
                    notifier._log_msg("warning", f"ip addr add {addr}: {err[:60]}")

            # 4. Set MTU and bring interface up
            self._run([IP_BIN, "link", "set", "mtu", mtu, "up", "dev", iface])

            # 5. Endpoint-specific route via original gateway
            if endpoint_ip and gw_ip:
                self._run([IP_BIN, "route", "add", f"{endpoint_ip}/32", "via", gw_ip])

            # 6. Routes for AllowedIPs
            for cidr in allowed_ips:
                if cidr == "0.0.0.0/0":
                    # Split into two /1 routes — higher specificity than default route,
                    # avoids conflicts with the existing default route
                    self._run([IP_BIN, "route", "add", "0.0.0.0/1", "dev", iface])
                    self._run([IP_BIN, "route", "add", "128.0.0.0/1", "dev", iface])
                elif cidr == "::/0":
                    self._run([IP_BIN, "-6", "route", "add", "::/1", "dev", iface])
                    self._run([IP_BIN, "-6", "route", "add", "8000::/1", "dev", iface])
                else:
                    self._run([IP_BIN, "route", "add", cidr, "dev", iface])

            # 7. Set DNS (back up resolv.conf first)
            if dns:
                self._save_dns()
                self._write_dns(dns)

            # 8. Wait for WireGuard handshake — ensures the tunnel actually works
            #    before signalling "Connected"
            self._wait_for_handshake(iface)

            # 9. Enable Kill Switch
            if self._kill_switch_enabled():
                kill_switch.enable(iface, endpoint_ip or "", endpoint_port)

        finally:
            try:
                os.unlink(stripped)
            except OSError:
                pass

        return True, ""

    def _wg_down(self, conf_path: str, disable_kill_switch: bool = True) -> tuple:
        """
        Tears down a WireGuard tunnel.
        Functionally equivalent to: wg-quick down <conf>
        disable_kill_switch=False: Kill Switch stays active (for leak-free reconnect).
        """
        iface = self._config_name(conf_path)

        # Disable Kill Switch (default) — prevents stale iptables rules.
        # With disable_kill_switch=False it stays active (reconnect to same server).
        if disable_kill_switch:
            kill_switch.disable()

        # Check if interface even exists
        rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
        if rc == 0 and iface not in out.split():
            return True, ""  # Already down

        # Restore DNS
        self._restore_dns()

        # Remove endpoint route (lives on physical interface, not on wg interface)
        endpoint_ip = self._state.pop("_endpoint_ip", None)
        if endpoint_ip:
            self._run([IP_BIN, "route", "del", f"{endpoint_ip}/32"])
            self._save_state()

        # Delete interface (automatically removes all associated routes)
        rc, _, err = self._run([IP_BIN, "link", "del", iface])
        if rc != 0:
            combined = err.lower()
            if "not found" in combined or "does not exist" in combined:
                return True, ""
            return False, f"ip link del: {err[:60]}"

        return True, ""

    def _bring_down_if_up(self, conf_path: str):
        """Best-effort: tear down tunnel, ignore errors."""
        if conf_path:
            self._wg_down(conf_path)

    def _verify_tunnel(self, interface_name: str) -> bool:
        """Checks whether the WireGuard interface is active."""
        try:
            rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
            if rc != 0:
                return True  # wg not available → optimistic
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
            notifier._log_msg("warning", "cycle_next: switch already in progress — ignored")
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
        Checks whether the WireGuard tunnel is active and functional.
        Criteria: interface must exist AND handshake was completed successfully.
        For old handshakes (idle tunnel > 3 min without traffic): send a probe and wait
        for WireGuard to initiate a new handshake — distinguishes idle from server-down.
        """
        conf_path = self._current_config_path()
        if not conf_path:
            return False
        iface = self._config_name(conf_path)

        # 1. Interface must exist
        rc, out, _ = self._run([WG_BIN, "show", "interfaces"])
        if rc != 0:
            return True  # wg not available → optimistic
        if iface not in out.strip().split():
            return False

        # 2. Check handshake timestamp
        rc, out, _ = self._run([WG_BIN, "show", iface, "latest-handshakes"])
        if rc != 0:
            return True  # Fallback optimistic

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
            return False  # No handshake completed yet

        if (time.time() - ts) < 180:
            return True  # Fresh handshake → tunnel definitely active

        # Handshake > 3 min old: could be idle (no traffic → no rekey)
        # or server is down. Send probe and wait briefly.
        return self._probe_handshake(iface, ts)

    def _probe_handshake(self, iface: str, old_ts: int) -> bool:
        """
        Sends a UDP packet to trigger a WireGuard handshake.
        Returns True if the handshake timestamp updates within 3s
        (tunnel was just idle), False if no update occurs (server likely down).
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
                                return True  # Handshake renewed → server reachable
                        except ValueError:
                            pass

        notifier._log_msg("warning", f"is_tunnel_up: no handshake update after probe ({iface})")
        return False

    def _wait_for_handshake(self, iface: str, timeout: float = 8.0) -> bool:
        """
        Waits until WireGuard completes a NEW handshake.
        Reads the baseline timestamp first — returns True only when a
        NEWER timestamp appears. Prevents false positives from a stale
        handshake of a previous session (e.g. interface still exists).
        """
        # Read baseline timestamp (0 if interface is fresh or no handshake yet)
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

        # Send UDP packet — routed via 0.0.0.0/1 route through WireGuard,
        # triggers handshake initiation in the WireGuard kernel module
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
                                notifier._log_msg("info", f"WireGuard handshake completed ({iface})")
                                return True
                        except ValueError:
                            pass
            time.sleep(0.3)

        notifier._log_msg("warning", f"WireGuard handshake timeout after {timeout}s ({iface}) — continuing")
        return False

    def _acquire_switch_lock(self):
        """Non-blocking exclusive lock. Returns (True, file) or (False, None).
        On non-Linux platforms (no fcntl): always succeeds (no-op)."""
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
        Synchronises iptables rules with the current Kill Switch setting.
        - Setting=True, iptables=off, tunnel up  → enable
        - Setting=False, iptables=on             → disable immediately
        """
        ks_setting = self._kill_switch_enabled()
        ks_active = kill_switch.is_enabled()

        if ks_setting and not ks_active and self.is_tunnel_up():
            iface = self._config_name(self._current_config_path())
            endpoint_ip = self._state.get("_endpoint_ip", "")
            endpoint_port = self._state.get("_endpoint_port", 51820)
            kill_switch.enable(iface, endpoint_ip, endpoint_port)
            notifier._log_msg("info", "Kill Switch sync: enabled (setting=on, tunnel up)")
        elif not ks_setting and ks_active:
            kill_switch.disable()
            notifier._log_msg("info", "Kill Switch sync: disabled (setting=off)")

    def auto_reconnect(self):
        if not self._configs:
            return
        acquired, lock_file = self._acquire_switch_lock()
        if not acquired:
            notifier._log_msg("info", "auto_reconnect: switch in progress — skipped")
            return
        try:
            self._load_state()  # Reload state — switch.py may have changed the index
            if not self.is_tunnel_up():
                conf_path = self._current_config_path()
                server_name = self._config_name(conf_path)
                ks_was_active = kill_switch.is_enabled()
                old_endpoint = self._state.get("_endpoint_ip", "")       # Save BEFORE _wg_down!
                old_endpoint_port = self._state.get("_endpoint_port", 51820)
                notifier.reconnecting(server_name)

                # Keep Kill Switch if possible — no IP leak during reconnect
                self._wg_down(conf_path, disable_kill_switch=not ks_was_active)
                # Restore endpoint IP/port as fallback — _wg_down() removes them from
                # state, but _wg_up() needs them when Kill Switch blocks DNS
                if old_endpoint:
                    self._state["_endpoint_ip"] = old_endpoint
                    self._state["_endpoint_port"] = old_endpoint_port
                ok, err = self._wg_up(conf_path)

                # Success only if interface is up AND handshake occurred.
                # ts=0 → WireGuard has no session → count as failure so that
                # auto-cycle after 3 failures kicks in (instead of endless reconnect loop).
                tunnel_ok = False
                if ok and self._verify_tunnel(server_name):
                    rc, out, _ = self._run([WG_BIN, "show", server_name, "latest-handshakes"])
                    if rc != 0:
                        tunnel_ok = True  # wg not available → optimistic
                    else:
                        for line in out.strip().splitlines():
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                try:
                                    if int(parts[-1]) > 0:
                                        tunnel_ok = True
                                    break
                                except ValueError:
                                    pass

                if tunnel_ok:
                    self._reconnect_failures = 0
                    notifier.connected(server_name)
                else:
                    self._reconnect_failures += 1
                    notifier._log_msg("warning",
                        f"Reconnect failed ({server_name}), attempt {self._reconnect_failures}")

                    if self._reconnect_failures >= 3 and len(self._configs) > 1:
                        # Server permanently down → switch to next
                        current_idx = self._state.get("index", 0)
                        next_idx = (current_idx + 1) % len(self._configs)
                        next_conf = self._configs[next_idx]
                        next_server = self._config_name(next_conf)
                        notifier._log_msg("warning",
                            f"Server {server_name} permanently down — switching to {next_server}")

                        self._state["index"] = next_idx
                        self._save_state()
                        self._reconnect_failures = 0

                        # Bring up new tunnel (Kill Switch still active with old rules)
                        ok2, _ = self._wg_up(next_conf)
                        new_endpoint = self._state.get("_endpoint_ip", "")
                        new_endpoint_port = self._state.get("_endpoint_port", 51820)
                        if ok2 and ks_was_active:
                            # Atomic rule swap: old_iface→new_iface, no leak
                            kill_switch.swap_server(next_server, new_endpoint,
                                                    server_name, old_endpoint,
                                                    new_endpoint_port, old_endpoint_port)
                        elif not ok2:
                            notifier.error(f"Auto-cycle failed: {next_server}")
                    elif self._kill_switch_enabled():
                        notifier.kill_switch_blocking()
                    else:
                        notifier.error(f"Reconnect failed — {server_name}: {err}")
            self._sync_kill_switch()
        finally:
            self._release_switch_lock(lock_file)
