"""Tests für resources/lib/wg_manager.py — nur pure Python-Logik"""
import json
import os
import tempfile
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
             patch.object(mgr, "_resolve_endpoint_ip", return_value=None):
            mgr._wg_up(str(conf))

        assert "10.0.0.2/32" in addr_calls
        assert "fd00::2/128" in addr_calls
