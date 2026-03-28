"""Tests für resources/lib/kill_switch.py"""
import subprocess
from unittest.mock import call, patch

import pytest

import resources.lib.kill_switch as ks


@pytest.fixture(autouse=True)
def reset_iptables_path():
    """Stellt sicher, dass _find_iptables einen bekannten Pfad liefert."""
    with patch("os.path.isfile", return_value=True):
        yield


class TestIsEnabled:
    def test_returns_true_when_chain_in_output(self):
        with patch("resources.lib.kill_switch._run", return_value=(0, "")) as mock_run:
            assert ks.is_enabled() is True
            mock_run.assert_called_once_with(["-C", "OUTPUT", "-j", ks.CHAIN])

    def test_returns_false_when_chain_missing(self):
        with patch("resources.lib.kill_switch._run", return_value=(1, "No such rule")):
            assert ks.is_enabled() is False


class TestEnable:
    def test_does_not_touch_input_chain(self):
        calls = []
        with patch("resources.lib.kill_switch._run", side_effect=lambda a: (calls.append(a), (0, ""))[1]):
            with patch("resources.lib.kill_switch.is_enabled", return_value=False):
                ks.enable("wg0", "1.2.3.4")

        hooks_used = [c[0] for c in calls if c[0] in ("-I", "-D")]
        for c in calls:
            if len(c) >= 3 and c[0] == "-I":
                assert c[1] != "INPUT", "Kill Switch darf INPUT-Chain nicht einhängen"

    def test_hooks_output_and_forward(self):
        inserted_hooks = []
        def fake_run(args):
            if args[0] == "-I":
                inserted_hooks.append(args[1])
            return 0, ""

        with patch("resources.lib.kill_switch._run", side_effect=fake_run):
            with patch("resources.lib.kill_switch.is_enabled", return_value=False):
                ks.enable("wg0", "1.2.3.4")

        assert "OUTPUT" in inserted_hooks
        assert "FORWARD" in inserted_hooks
        assert "INPUT" not in inserted_hooks

    def test_skips_if_already_enabled(self):
        with patch("resources.lib.kill_switch.is_enabled", return_value=True):
            with patch("resources.lib.kill_switch._run") as mock_run:
                result = ks.enable("wg0", "1.2.3.4")
                assert result is True
                mock_run.assert_not_called()

    def test_returns_false_on_rule_error(self):
        def fail_on_chain(args):
            if args[0] == "-A":
                return 1, "iptables: error"
            return 0, ""

        with patch("resources.lib.kill_switch._run", side_effect=fail_on_chain):
            with patch("resources.lib.kill_switch.is_enabled", return_value=False):
                with patch("resources.lib.kill_switch.disable"):
                    result = ks.enable("wg0", "1.2.3.4")
                    assert result is False


class TestDisable:
    def test_removes_output_and_forward_hooks(self):
        deleted_hooks = []
        def fake_run(args):
            if args[0] == "-D":
                deleted_hooks.append(args[1])
            return 0, ""

        with patch("resources.lib.kill_switch._run", side_effect=fake_run):
            ks.disable()

        assert "OUTPUT" in deleted_hooks
        assert "FORWARD" in deleted_hooks
        assert "INPUT" not in deleted_hooks

    def test_flushes_and_deletes_chain(self):
        called = []
        with patch("resources.lib.kill_switch._run", side_effect=lambda a: (called.append(tuple(a)), (0, ""))[1]):
            ks.disable()

        assert ("-F", ks.CHAIN) in called
        assert ("-X", ks.CHAIN) in called
