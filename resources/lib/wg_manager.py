import glob
import json
import os
import subprocess

from resources.lib import notifier

WG_QUICK = "/usr/bin/wg-quick"
WG_BIN = "/usr/bin/wg"


class WireGuardManager:
    def __init__(self, addon_path: str):
        self._configs_dir = os.path.join(addon_path, "configs")
        self._state_file = os.path.join(addon_path, "state.json")
        self._configs = []
        self._state = {}
        self._load_configs()
        self._load_state()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
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

        # Guard against out-of-range index
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

    def _check_wg_quick_available(self) -> bool:
        if not os.path.isfile(WG_QUICK):
            notifier.error(f"wg-quick not found at {WG_QUICK}")
            return False
        return True

    def _wg_quick_up(self, conf_path: str) -> tuple:
        try:
            result = subprocess.run(
                [WG_QUICK, "up", conf_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return (True, "")
            return (False, result.stderr[:80])
        except subprocess.TimeoutExpired:
            return (False, "timed out after 15s")
        except FileNotFoundError:
            return (False, f"wg-quick not found at {WG_QUICK}")

    def _wg_quick_down(self, conf_path: str) -> tuple:
        try:
            result = subprocess.run(
                [WG_QUICK, "down", conf_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return (True, "")
            combined = (result.stdout + result.stderr).lower()
            if "not a wireguard interface" in combined or "does not exist" in combined:
                return (True, "")
            return (False, result.stderr[:80])
        except subprocess.TimeoutExpired:
            return (False, "timed out after 15s")
        except FileNotFoundError:
            return (False, f"wg-quick not found at {WG_QUICK}")

    def _bring_down_if_up(self, conf_path: str):
        if conf_path:
            self._wg_quick_down(conf_path)

    def _verify_tunnel(self, interface_name: str) -> bool:
        try:
            result = subprocess.run(
                [WG_BIN, "show", "interfaces"],
                capture_output=True, text=True, timeout=5
            )
            interfaces = result.stdout.strip().split()
            return interface_name in interfaces
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # wg binary missing or hung — be optimistic
            return True

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def restore(self):
        if not self._configs:
            notifier.error("No .conf files found in configs/")
            return
        if not self._check_wg_quick_available():
            return

        conf_path = self._current_config_path()
        server_name = self._config_name(conf_path)
        notifier.connecting(server_name)
        self._bring_down_if_up(conf_path)
        ok, err = self._wg_quick_up(conf_path)
        if not ok:
            notifier.error(f"{server_name}: {err}")
            return
        if self._verify_tunnel(server_name):
            notifier.connected(server_name)
        else:
            notifier.error(f"{server_name}: tunnel not visible after up")

    def cycle_next(self):
        if not self._configs:
            notifier.error("No .conf files found in configs/")
            return
        if not self._check_wg_quick_available():
            return

        current_conf = self._current_config_path()
        self._bring_down_if_up(current_conf)

        current_idx = self._state.get("index", 0)
        next_idx = (current_idx + 1) % len(self._configs)
        self._state["index"] = next_idx
        self._save_state()

        new_conf = self._current_config_path()
        new_server = self._config_name(new_conf)
        notifier.connecting(new_server)
        ok, err = self._wg_quick_up(new_conf)
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
            ok, err = self._wg_quick_up(conf_path)
            if not ok:
                notifier.error(f"Reconnect failed — {server_name}: {err}")
