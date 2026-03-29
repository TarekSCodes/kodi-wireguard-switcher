"""Tests für resources/lib/wg_manager.py — nur pure Python-Logik"""
import json
import os
import sys
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

# xbmcaddon muss vor dem Import von wg_manager verfügbar sein (bereits in conftest gemockt)
import xbmcaddon

import resources.lib.wg_manager as wgm
from resources.lib.wg_manager import WireGuardManager


@pytest.fixture
def tmp_addon(tmp_path):
    """Erzeugt eine minimale Addon-Verzeichnisstruktur mit einer .conf-Datei."""
    configs = tmp_path / "configs"
    configs.mkdir()
    conf = configs / "Server-A.conf"
    conf.write_text(
        "[Interface]\n"
        "PrivateKey = AAAA\n"
        "Address = 10.0.0.2/32\n"
        "DNS = 1.1.1.1\n"
        "[Peer]\n"
        "PublicKey = BBBB\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )
    return tmp_path


@pytest.fixture
def manager(tmp_addon):
    xbmcaddon.Addon.return_value.getSetting.return_value = "false"
    return WireGuardManager(str(tmp_addon))


class TestParseWgConf:
    def test_parses_interface(self, manager, tmp_addon):
        conf_path = str(tmp_addon / "configs" / "Server-A.conf")
        result = manager._parse_wg_conf(conf_path)
        assert result["interface"]["Address"] == "10.0.0.2/32"
        assert result["interface"]["DNS"] == "1.1.1.1"
        assert result["interface"]["PrivateKey"] == "AAAA"

    def test_parses_peer(self, manager, tmp_addon):
        conf_path = str(tmp_addon / "configs" / "Server-A.conf")
        result = manager._parse_wg_conf(conf_path)
        assert len(result["peers"]) == 1
        assert result["peers"][0]["Endpoint"] == "vpn.example.com:51820"
        assert result["peers"][0]["AllowedIPs"] == "0.0.0.0/0"


class TestWriteStrippedConf:
    def test_strips_address_and_dns(self, manager, tmp_addon):
        conf_path = str(tmp_addon / "configs" / "Server-A.conf")
        data = manager._parse_wg_conf(conf_path)
        stripped = manager._write_stripped_conf(data)
        try:
            content = open(stripped).read().lower()
            assert "address" not in content
            assert "dns" not in content
            assert "privatekey" in content
        finally:
            os.unlink(stripped)

    def test_includes_peer_section(self, manager, tmp_addon):
        conf_path = str(tmp_addon / "configs" / "Server-A.conf")
        data = manager._parse_wg_conf(conf_path)
        stripped = manager._write_stripped_conf(data)
        try:
            content = open(stripped).read()
            assert "[Peer]" in content
            assert "PublicKey" in content
        finally:
            os.unlink(stripped)


class TestConfigName:
    def test_strips_directory_and_extension(self, manager, tmp_addon):
        path = str(tmp_addon / "configs" / "HideMe-DE.conf")
        assert manager._config_name(path) == "HideMe-DE"


class TestLoadState:
    def test_creates_default_state_when_file_missing(self, tmp_addon):
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        assert mgr._state["index"] == 0

    def test_resets_out_of_range_index(self, tmp_addon):
        state_file = tmp_addon / "state.json"
        state_file.write_text(json.dumps({"index": 99, "current_server": "gone"}))
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        assert mgr._state["index"] == 0

    def test_preserves_valid_index(self, tmp_addon):
        state_file = tmp_addon / "state.json"
        state_file.write_text(json.dumps({"index": 0, "current_server": "Server-A"}))
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        assert mgr._state["index"] == 0


class TestAutoReconnectStateSync:
    def test_reloads_state_before_check(self, tmp_addon):
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        mgr._state["index"] = 0

        # Simuliere: switch.py hat Index auf 0 gelassen, Tunnel ist oben
        with patch.object(mgr, "_load_state") as mock_load, \
             patch.object(mgr, "is_tunnel_up", return_value=True), \
             patch.object(mgr, "_sync_kill_switch"):
            mgr.auto_reconnect()
            mock_load.assert_called_once()

    def test_does_not_reconnect_when_tunnel_up(self, tmp_addon):
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=True), \
             patch.object(mgr, "_sync_kill_switch"), \
             patch.object(mgr, "_wg_up") as mock_up:
            mgr.auto_reconnect()
            mock_up.assert_not_called()


class TestEndpointPortInWgUp:
    """Stellt sicher dass der Endpoint-Port aus der Config an Kill Switch weitergegeben wird."""

    def test_custom_port_passed_to_kill_switch_enable(self, tmp_addon):
        """HideMe-Style Config mit Port 428 → Kill Switch bekommt 428."""
        conf = tmp_addon / "configs" / "HideMe-Test.conf"
        conf.write_text(
            "[Interface]\n"
            "PrivateKey = AAAA\n"
            "Address = 10.0.0.2/32\n"
            "[Peer]\n"
            "PublicKey = BBBB\n"
            "Endpoint = vpn.example.com:428\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        xbmcaddon.Addon.return_value.getSetting.return_value = "true"  # Kill Switch an
        mgr = WireGuardManager(str(tmp_addon))

        enable_calls = []

        with patch.object(mgr, "_run", return_value=(0, "", "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch.object(mgr, "_write_stripped_conf", return_value="/tmp/fake.conf"), \
             patch("os.unlink"), \
             patch.object(mgr, "_get_default_gateway", return_value=("10.0.0.1", "eth0")), \
             patch.object(mgr, "_resolve_endpoint_ip", return_value="1.2.3.4"), \
             patch.object(mgr, "_wait_for_handshake", return_value=True), \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False
            mock_ks.enable.side_effect = lambda *a, **kw: enable_calls.append(a)
            mgr._wg_up(str(conf))

        assert len(enable_calls) == 1
        _, _, port = enable_calls[0]
        assert port == 428, f"Port 428 erwartet, got: {port}"

    def test_default_port_51820_when_missing(self, tmp_addon):
        """Config ohne Port-Suffix → Fallback 51820."""
        conf = tmp_addon / "configs" / "Server-NoPort.conf"
        conf.write_text(
            "[Interface]\n"
            "PrivateKey = AAAA\n"
            "Address = 10.0.0.2/32\n"
            "[Peer]\n"
            "PublicKey = BBBB\n"
            "Endpoint = 1.2.3.4:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        xbmcaddon.Addon.return_value.getSetting.return_value = "true"
        mgr = WireGuardManager(str(tmp_addon))

        enable_calls = []

        with patch.object(mgr, "_run", return_value=(0, "", "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch.object(mgr, "_write_stripped_conf", return_value="/tmp/fake.conf"), \
             patch("os.unlink"), \
             patch.object(mgr, "_get_default_gateway", return_value=("10.0.0.1", "eth0")), \
             patch.object(mgr, "_resolve_endpoint_ip", return_value="1.2.3.4"), \
             patch.object(mgr, "_wait_for_handshake", return_value=True), \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False
            mock_ks.enable.side_effect = lambda *a, **kw: enable_calls.append(a)
            mgr._wg_up(str(conf))

        _, _, port = enable_calls[0]
        assert port == 51820


class TestAddrSplitInWgUp:
    """Stellt sicher dass komma-separierte Adressen einzeln übergeben werden."""

    def test_multiple_addresses_called_separately(self, tmp_addon):
        conf = tmp_addon / "configs" / "Multi.conf"
        conf.write_text(
            "[Interface]\n"
            "PrivateKey = AAAA\n"
            "Address = 10.0.0.2/32, fd00::2/128\n"
            "[Peer]\n"
            "PublicKey = BBBB\n"
            "Endpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        addr_calls = []
        def fake_run(cmd):
            if "addr" in cmd and "add" in cmd:
                addr_calls.append(cmd[cmd.index("add") + 1])
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=True), \
             patch("resources.lib.wg_manager.kill_switch"), \
             patch.object(mgr, "_write_stripped_conf", return_value="/tmp/fake.conf"), \
             patch("os.unlink"), \
             patch.object(mgr, "_get_default_gateway", return_value=(None, None)), \
             patch.object(mgr, "_resolve_endpoint_ip", return_value=None), \
             patch.object(mgr, "_wait_for_handshake", return_value=True):
            mgr._wg_up(str(conf))

        assert "10.0.0.2/32" in addr_calls
        assert "fd00::2/128" in addr_calls


class TestSwitchLock:
    @pytest.mark.skipif(sys.platform == "win32", reason="fcntl nicht auf Windows — Lock ist no-op")
    def test_second_cycle_next_blocked_while_first_runs(self, tmp_addon):
        """Zweiter cycle_next()-Aufruf während erstem läuft wird ignoriert (nicht gecrasht)."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        switch_started = threading.Event()
        allow_finish = threading.Event()
        wg_up_calls = []

        def slow_wg_up(conf):
            wg_up_calls.append(conf)
            switch_started.set()
            allow_finish.wait(timeout=2)
            return True, ""

        with patch.object(mgr, "_check_requirements", return_value=True), \
             patch.object(mgr, "_bring_down_if_up"), \
             patch.object(mgr, "_wg_up", side_effect=slow_wg_up), \
             patch.object(mgr, "_verify_tunnel", return_value=True), \
             patch("resources.lib.wg_manager.notifier"):

            t1 = threading.Thread(target=mgr.cycle_next)
            t1.start()
            switch_started.wait(timeout=2)

            # Zweiter Aufruf während t1 noch läuft
            mgr.cycle_next()

            allow_finish.set()
            t1.join(timeout=3)

        # Nur ein _wg_up wurde aufgerufen — zweiter Aufruf wurde blockiert
        assert len(wg_up_calls) == 1

    def test_auto_reconnect_skips_when_locked(self, tmp_addon):
        """auto_reconnect() überspringt Reconnect wenn Switch-Lock gehalten wird."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        acquired, lf = mgr._acquire_switch_lock()
        assert acquired

        try:
            with patch.object(mgr, "_wg_up") as mock_up, \
                 patch("resources.lib.wg_manager.notifier"):
                mgr.auto_reconnect()
                mock_up.assert_not_called()
        finally:
            mgr._release_switch_lock(lf)

    def test_lock_released_after_wg_up_error(self, tmp_addon):
        """Lock wird im finally freigegeben — auch wenn _wg_up() fehlschlägt."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        with patch.object(mgr, "_check_requirements", return_value=True), \
             patch.object(mgr, "_bring_down_if_up"), \
             patch.object(mgr, "_wg_up", return_value=(False, "fake error")), \
             patch("resources.lib.wg_manager.notifier"):
            mgr.cycle_next()

        # Nach dem fehlgeschlagenen cycle_next muss Lock wieder frei sein
        acquired, lf = mgr._acquire_switch_lock()
        assert acquired, "Lock sollte nach Fehler freigegeben sein"
        mgr._release_switch_lock(lf)


class TestWaitForHandshake:
    def test_returns_true_when_handshake_detected(self, manager):
        """Gibt True zurück sobald ein NEUERER Timestamp als der Baseline erscheint."""
        pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        call_count = [0]
        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                call_count[0] += 1
                if call_count[0] == 1:  # Baseline-Abfrage: noch kein Handshake
                    return 0, f"{pubkey}\t0\n", ""
                return 0, f"{pubkey}\t1711650000\n", ""  # Frischer Handshake
            return 0, "", ""

        with patch.object(manager, "_run", side_effect=fake_run), \
             patch("resources.lib.wg_manager.socket"), \
             patch("resources.lib.wg_manager.notifier"):
            result = manager._wait_for_handshake("HideMe-Test", timeout=2.0)

        assert result is True

    def test_ignores_stale_baseline_timestamp(self, manager):
        """Staler Baseline-Timestamp (Interface nicht sauber getrennt) wird ignoriert —
        wartet auf einen NEUEREN Timestamp."""
        pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        stale_ts = 1700000000
        new_ts   = 1711650000

        call_count = [0]
        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                call_count[0] += 1
                if call_count[0] == 1:          # Baseline: staler Timestamp
                    return 0, f"{pubkey}\t{stale_ts}\n", ""
                if call_count[0] == 2:          # Erster Poll: noch stale
                    return 0, f"{pubkey}\t{stale_ts}\n", ""
                return 0, f"{pubkey}\t{new_ts}\n", ""  # Zweiter Poll: frischer HS
            return 0, "", ""

        with patch.object(manager, "_run", side_effect=fake_run), \
             patch("resources.lib.wg_manager.socket"), \
             patch("resources.lib.wg_manager.notifier"):
            result = manager._wait_for_handshake("HideMe-Test", timeout=5.0)

        assert result is True
        assert call_count[0] >= 3  # Baseline + mind. 2 Polls

    def test_returns_false_on_timeout(self, manager):
        """Gibt False zurück wenn Handshake nicht rechtzeitig stattfindet."""
        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                return 0, "", ""  # Kein Timestamp
            return 0, "", ""

        with patch.object(manager, "_run", side_effect=fake_run), \
             patch("resources.lib.wg_manager.socket"), \
             patch("resources.lib.wg_manager.time") as mock_time, \
             patch("resources.lib.wg_manager.notifier"):
            # Zeit läuft sofort ab
            mock_time.time.side_effect = [0.0, 0.0, 99.0]
            mock_time.sleep = MagicMock()
            result = manager._wait_for_handshake("HideMe-Test", timeout=1.0)

        assert result is False

    def test_handshake_wait_always_called(self, tmp_addon):
        """_wait_for_handshake() wird immer aufgerufen — unabhängig vom Kill Switch Setting."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"  # Kill Switch aus
        mgr = WireGuardManager(str(tmp_addon))

        with patch.object(mgr, "_run", return_value=(0, "", "")), \
             patch("resources.lib.wg_manager.kill_switch"), \
             patch.object(mgr, "_write_stripped_conf", return_value="/tmp/fake.conf"), \
             patch("os.unlink"), \
             patch.object(mgr, "_get_default_gateway", return_value=(None, None)), \
             patch.object(mgr, "_resolve_endpoint_ip", return_value=None), \
             patch.object(mgr, "_wait_for_handshake") as mock_hs, \
             patch("resources.lib.wg_manager.notifier"):
            mock_hs.return_value = True
            mgr._wg_up(str(tmp_addon / "configs" / "Server-A.conf"))

        mock_hs.assert_called_once()

    def test_handshake_wait_called_before_kill_switch(self, tmp_addon):
        """_wait_for_handshake() wird aufgerufen bevor Kill Switch aktiviert wird."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "true"  # Kill Switch an
        mgr = WireGuardManager(str(tmp_addon))

        call_order = []

        with patch.object(mgr, "_run", return_value=(0, "", "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch.object(mgr, "_write_stripped_conf", return_value="/tmp/fake.conf"), \
             patch("os.unlink"), \
             patch.object(mgr, "_get_default_gateway", return_value=(None, None)), \
             patch.object(mgr, "_resolve_endpoint_ip", return_value=None), \
             patch.object(mgr, "_wait_for_handshake", side_effect=lambda *a, **kw: call_order.append("handshake") or True), \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False
            mock_ks.enable.side_effect = lambda *a: call_order.append("kill_switch")
            mgr._wg_up(str(tmp_addon / "configs" / "Server-A.conf"))

        assert call_order.index("handshake") < call_order.index("kill_switch")


class TestProbeHandshake:
    def test_returns_true_when_handshake_updates(self, manager):
        """Wenn Handshake-Timestamp sich aktualisiert → True (idle Tunnel, Server erreichbar)."""
        pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        old_ts = 1000
        new_ts = 1001

        call_count = [0]
        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                call_count[0] += 1
                if call_count[0] >= 2:
                    return 0, f"{pubkey}\t{new_ts}\n", ""
                return 0, f"{pubkey}\t{old_ts}\n", ""
            return 0, "", ""

        with patch.object(manager, "_run", side_effect=fake_run), \
             patch("resources.lib.wg_manager.socket"), \
             patch("resources.lib.wg_manager.time") as mock_time:
            mock_time.time.side_effect = [0.0, 0.0, 0.5]
            mock_time.sleep = MagicMock()
            result = manager._probe_handshake("Server-A", old_ts)

        assert result is True

    def test_returns_false_when_no_handshake_update(self, manager):
        """Wenn kein Handshake-Update innerhalb 3s → False (Server down)."""
        pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        old_ts = 1000

        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                return 0, f"{pubkey}\t{old_ts}\n", ""
            return 0, "", ""

        with patch.object(manager, "_run", side_effect=fake_run), \
             patch("resources.lib.wg_manager.socket"), \
             patch("resources.lib.wg_manager.time") as mock_time, \
             patch("resources.lib.wg_manager.notifier"):
            mock_time.time.side_effect = [0.0, 0.0, 0.0, 99.0]
            mock_time.sleep = MagicMock()
            result = manager._probe_handshake("Server-A", old_ts)

        assert result is False

    def test_is_tunnel_up_uses_probe_for_stale_handshake(self, tmp_addon):
        """Bei altem Handshake (> 180s): _probe_handshake wird aufgerufen."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        stale_ts = int(time.time()) - 200

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"PUBKEY\t{stale_ts}\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run), \
             patch.object(mgr, "_probe_handshake", return_value=True) as mock_probe:
            result = mgr.is_tunnel_up()

        mock_probe.assert_called_once_with("Server-A", stale_ts)
        assert result is True  # Probe sagt: Server erreichbar

    def test_is_tunnel_up_no_probe_for_fresh_handshake(self, tmp_addon):
        """Bei frischem Handshake (< 180s): kein Probe-Aufruf nötig."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        fresh_ts = int(time.time()) - 30

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"PUBKEY\t{fresh_ts}\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run), \
             patch.object(mgr, "_probe_handshake") as mock_probe:
            result = mgr.is_tunnel_up()

        mock_probe.assert_not_called()
        assert result is True


class TestAutoReconnectNoLeak:
    def test_kill_switch_not_disabled_during_reconnect_when_active(self, tmp_addon):
        """Kill Switch bleibt aktiv während Reconnect zum gleichen Server."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        disabled_calls = []

        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=False), \
             patch.object(mgr, "_verify_tunnel", return_value=True), \
             patch.object(mgr, "_wg_up", return_value=(True, "")), \
             patch.object(mgr, "_sync_kill_switch"), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = True  # Kill Switch war aktiv
            mock_ks.disable.side_effect = lambda: disabled_calls.append("disable")
            mgr.auto_reconnect()

        assert len(disabled_calls) == 0, "Kill Switch darf beim Reconnect nicht deaktiviert werden"

    def test_failure_counted_when_handshake_times_out(self, tmp_addon):
        """Interface existiert aber ts=0 → kein echter Handshake → Fehler zählen."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        def fake_run(cmd):
            if "latest-handshakes" in cmd:
                return 0, "PUBKEY\t0\n", ""  # kein Handshake
            return 0, "", ""

        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=False), \
             patch.object(mgr, "_verify_tunnel", return_value=True), \
             patch.object(mgr, "_wg_up", return_value=(True, "")), \
             patch.object(mgr, "_wg_down", return_value=(True, "")), \
             patch.object(mgr, "_run", side_effect=fake_run), \
             patch.object(mgr, "_sync_kill_switch"), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False
            mgr.auto_reconnect()

        assert mgr._reconnect_failures == 1

    def test_kill_switch_disabled_when_not_active(self, tmp_addon):
        """Kill Switch war aus → _wg_down darf ihn ausschalten (default behavior)."""
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=False), \
             patch.object(mgr, "_verify_tunnel", return_value=True), \
             patch.object(mgr, "_wg_up", return_value=(True, "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False  # Kill Switch war aus
            mgr.auto_reconnect()

        mock_ks.disable.assert_called()

    def test_auto_cycle_after_three_failures(self, tmp_addon):
        """Nach 3 Fehlern: wechselt zum nächsten Server."""
        # Zweite Config anlegen
        (tmp_addon / "configs" / "Server-B.conf").write_text(
            "[Interface]\nPrivateKey = BBBB\nAddress = 10.0.0.3/32\n"
            "[Peer]\nPublicKey = CCCC\nEndpoint = vpn2.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))

        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=False), \
             patch.object(mgr, "_verify_tunnel", return_value=False), \
             patch.object(mgr, "_wg_up", return_value=(True, "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = False
            # 3 Fehler triggern
            for _ in range(3):
                mgr.auto_reconnect()

        # Index muss gewechselt haben
        assert mgr._state["index"] == 1
        assert mgr._reconnect_failures == 0

    def test_swap_server_called_on_auto_cycle_with_active_kill_switch(self, tmp_addon):
        """Bei Auto-Cycle mit aktivem Kill Switch: swap_server() für leckfreien Wechsel."""
        (tmp_addon / "configs" / "Server-B.conf").write_text(
            "[Interface]\nPrivateKey = BBBB\nAddress = 10.0.0.3/32\n"
            "[Peer]\nPublicKey = CCCC\nEndpoint = vpn2.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        mgr = WireGuardManager(str(tmp_addon))
        mgr._reconnect_failures = 2  # Nächster Fehler = Failure Nr. 3 → Cycle

        with patch.object(mgr, "_load_state"), \
             patch.object(mgr, "is_tunnel_up", return_value=False), \
             patch.object(mgr, "_verify_tunnel", return_value=False), \
             patch.object(mgr, "_wg_up", return_value=(True, "")), \
             patch("resources.lib.wg_manager.kill_switch") as mock_ks, \
             patch("resources.lib.wg_manager.notifier"):
            mock_ks.is_enabled.return_value = True  # Kill Switch aktiv
            mgr.auto_reconnect()

        mock_ks.swap_server.assert_called_once()


class TestIsTunnelUp:
    PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    def _make_mgr(self, tmp_addon):
        xbmcaddon.Addon.return_value.getSetting.return_value = "false"
        return WireGuardManager(str(tmp_addon))

    def test_returns_true_with_fresh_handshake(self, tmp_addon):
        """Frischer Handshake (vor 10s) → True."""
        mgr = self._make_mgr(tmp_addon)
        fresh_ts = int(time.time()) - 10

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"{self.PUBKEY}\t{fresh_ts}\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run):
            assert mgr.is_tunnel_up() is True

    def test_returns_false_with_stale_handshake_and_dead_server(self, tmp_addon):
        """Handshake älter als 3 Minuten + Probe schlägt fehl → False (Server ausgefallen)."""
        mgr = self._make_mgr(tmp_addon)
        stale_ts = int(time.time()) - 200

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"{self.PUBKEY}\t{stale_ts}\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run), \
             patch.object(mgr, "_probe_handshake", return_value=False):
            assert mgr.is_tunnel_up() is False

    def test_returns_true_with_stale_handshake_but_server_alive(self, tmp_addon):
        """Handshake älter als 3 Minuten, aber Probe erfolgreich → True (idle Tunnel)."""
        mgr = self._make_mgr(tmp_addon)
        stale_ts = int(time.time()) - 200

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"{self.PUBKEY}\t{stale_ts}\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run), \
             patch.object(mgr, "_probe_handshake", return_value=True):
            assert mgr.is_tunnel_up() is True

    def test_returns_false_when_no_handshake_yet(self, tmp_addon):
        """Timestamp 0 (noch kein Handshake) → False."""
        mgr = self._make_mgr(tmp_addon)

        def fake_run(cmd):
            if cmd[-1] == "interfaces":
                return 0, "Server-A", ""
            if "latest-handshakes" in cmd:
                return 0, f"{self.PUBKEY}\t0\n", ""
            return 0, "", ""

        with patch.object(mgr, "_run", side_effect=fake_run):
            assert mgr.is_tunnel_up() is False

    def test_returns_false_when_interface_missing(self, tmp_addon):
        """Interface existiert nicht → False."""
        mgr = self._make_mgr(tmp_addon)

        with patch.object(mgr, "_run", return_value=(0, "", "")):
            assert mgr.is_tunnel_up() is False

    def test_returns_true_optimistically_when_wg_unavailable(self, tmp_addon):
        """wg-Befehl schlägt fehl → True (optimistisch, kein Reboot-Loop)."""
        mgr = self._make_mgr(tmp_addon)

        with patch.object(mgr, "_run", return_value=(1, "", "command not found")):
            assert mgr.is_tunnel_up() is True
