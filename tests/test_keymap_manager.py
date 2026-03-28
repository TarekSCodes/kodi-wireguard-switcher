"""Tests für resources/lib/keymap_manager.py"""
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

import resources.lib.keymap_manager as km


@pytest.fixture
def tmp_keymap_dir(tmp_path):
    """Patcht translatePath so dass Keymaps in ein Temp-Verzeichnis gehen."""
    def fake_translate(path):
        # Verzeichnis-Anfragen (enden mit /)
        if path.endswith("/keymaps/") or path.endswith("\\keymaps\\"):
            return str(tmp_path) + "/"
        # Datei-Anfragen (z.B. special://userdata/keymaps/wireguard.xml)
        if "keymaps" in path:
            fname = path.split("/")[-1]
            return str(tmp_path / fname)
        return path

    with patch("xbmcvfs.translatePath", side_effect=fake_translate):
        yield tmp_path


class TestWriteKeymap:
    def test_creates_file_in_keymap_dir(self, tmp_keymap_dir):
        km.write_keymap("", button_code=None)
        assert (tmp_keymap_dir / "wireguard.xml").exists()

    def test_button_code_in_keyboard_section(self, tmp_keymap_dir):
        km.write_keymap("", button_code=61952)
        content = (tmp_keymap_dir / "wireguard.xml").read_text()
        assert '<key id="61952">' in content
        assert "<keyboard>" in content

    def test_button_code_not_in_remote_section(self, tmp_keymap_dir):
        km.write_keymap("", button_code=61952)
        content = (tmp_keymap_dir / "wireguard.xml").read_text()
        assert "<remote>" not in content

    def test_no_key_id_when_code_is_none(self, tmp_keymap_dir):
        km.write_keymap("", button_code=None)
        content = (tmp_keymap_dir / "wireguard.xml").read_text()
        assert 'key id=' not in content

    def test_always_contains_w_shortcut(self, tmp_keymap_dir):
        km.write_keymap("", button_code=None)
        content = (tmp_keymap_dir / "wireguard.xml").read_text()
        assert "<w>RunScript(service.wireguard.switcher)</w>" in content


class TestFindKeyConflict:
    def test_returns_none_when_no_conflict(self, tmp_keymap_dir):
        (tmp_keymap_dir / "other.xml").write_text('<keymap><global><keyboard><key id="99">noop</key></keyboard></global></keymap>')
        result = km.find_key_conflict(61952)
        assert result is None

    def test_returns_filename_on_conflict(self, tmp_keymap_dir):
        (tmp_keymap_dir / "zomboided.xml").write_text('<keymap><global><keyboard><key id="61952">cycle.py</key></keyboard></global></keymap>')
        result = km.find_key_conflict(61952)
        assert result == "zomboided.xml"

    def test_skips_own_keymap_file(self, tmp_keymap_dir):
        (tmp_keymap_dir / km.KEYMAP_FILENAME).write_text('<key id="61952">ours</key>')
        result = km.find_key_conflict(61952)
        assert result is None


class TestRemoveKeyFromFile:
    def test_removes_matching_line(self, tmp_keymap_dir):
        content = (
            '<keymap><global><keyboard>\n'
            '<key id="61952">cycle.py</key>\n'
            '<key id="99">other</key>\n'
            '</keyboard></global></keymap>\n'
        )
        (tmp_keymap_dir / "zomboided.xml").write_text(content)
        km.remove_key_from_file("zomboided.xml", 61952)
        result = (tmp_keymap_dir / "zomboided.xml").read_text()
        assert 'id="61952"' not in result
        assert 'id="99"' in result
