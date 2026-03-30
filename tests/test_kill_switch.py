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

    def test_uses_custom_port_in_endpoint_rule(self):
        """enable() mit endpoint_port=428 schreibt --dport 428 in die iptables-Regel."""
        rules_added = []

        def fake_run(args):
            if args[0] == "-A" and "--dport" in args:
                rules_added.append(args[args.index("--dport") + 1])
            return 0, ""

        with patch("resources.lib.kill_switch._run", side_effect=fake_run):
            with patch("resources.lib.kill_switch.is_enabled", return_value=False):
                ks.enable("wg0", "1.2.3.4", endpoint_port=428)

        assert "428" in rules_added, f"Port 428 erwartet, got: {rules_added}"
        assert "51820" not in rules_added, "Default-Port 51820 darf nicht verwendet werden"

    def test_defaults_to_51820_when_no_port_given(self):
        """enable() ohne endpoint_port → Fallback auf 51820."""
        rules_added = []

        def fake_run(args):
            if args[0] == "-A" and "--dport" in args:
                rules_added.append(args[args.index("--dport") + 1])
            return 0, ""

        with patch("resources.lib.kill_switch._run", side_effect=fake_run):
            with patch("resources.lib.kill_switch.is_enabled", return_value=False):
                ks.enable("wg0", "1.2.3.4")

        assert "51820" in rules_added

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


class TestSwapServer:
    def test_does_nothing_when_not_enabled(self):
        with patch("resources.lib.kill_switch.is_enabled", return_value=False):
            with patch("resources.lib.kill_switch._run") as mock_run:
                ks.swap_server("wg1", "2.2.2.2", "wg0", "1.1.1.1")
                mock_run.assert_not_called()

    def test_inserts_new_endpoint_before_removing_old(self):
        """Schritt 1 muss vor Schritt 2 erfolgen — kein Moment ohne Endpoint-Ausnahme."""
        call_order = []

        def fake_run(args):
            if args[0] == "-I" and "2.2.2.2" in args:
                call_order.append("insert_new_endpoint")
            elif args[0] == "-D" and "wg0" in args:
                call_order.append("delete_old_iface")
            elif args[0] == "-D" and "1.1.1.1" in args:
                call_order.append("delete_old_endpoint")
            elif args[0] == "-I" and "wg1" in args:
                call_order.append("insert_new_iface")
            elif args[0] == "-D" and "2.2.2.2" in args:
                call_order.append("delete_temp_endpoint")
            return 0, ""

        with patch("resources.lib.kill_switch.is_enabled", return_value=True):
            with patch("resources.lib.kill_switch._run", side_effect=fake_run):
                ks.swap_server("wg1", "2.2.2.2", "wg0", "1.1.1.1")

        assert call_order[0] == "insert_new_endpoint", "Neue Endpoint-Ausnahme muss zuerst kommen"
        assert call_order[-1] == "delete_temp_endpoint", "Temp-Ausnahme muss zuletzt entfernt werden"

    def test_skips_old_endpoint_delete_when_empty(self):
        """Wenn kein alter Endpoint bekannt: kein -D für leeren Endpoint."""
        deleted = []

        def fake_run(args):
            if args[0] == "-D":
                deleted.append(args)
            return 0, ""

        with patch("resources.lib.kill_switch.is_enabled", return_value=True):
            with patch("resources.lib.kill_switch._run", side_effect=fake_run):
                ks.swap_server("wg1", "2.2.2.2", "wg0", "")

        for d in deleted:
            assert "" not in d, "Kein Löschen von leerem Endpoint"

    def test_new_iface_rules_inserted_at_correct_positions(self):
        """Neue Interface-Regeln an Position 3 und 4 einfügen."""
        inserts = []

        def fake_run(args):
            if args[0] == "-I" and "wg1" in args:
                inserts.append((args[1], args[2]))  # (chain, position)
            return 0, ""

        with patch("resources.lib.kill_switch.is_enabled", return_value=True):
            with patch("resources.lib.kill_switch._run", side_effect=fake_run):
                ks.swap_server("wg1", "2.2.2.2", "wg0", "1.1.1.1")

        positions = {pos for _, pos in inserts}
        assert "3" in positions
        assert "4" in positions


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
