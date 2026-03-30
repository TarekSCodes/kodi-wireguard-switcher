import os
import subprocess

from resources.lib import notifier

CHAIN = "WG_KILL_SWITCH"
IPTABLES = "/usr/sbin/iptables"


def _find_iptables() -> str:
    for path in ("/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"):
        if os.path.isfile(path):
            return path
    return IPTABLES


def _run(args: list) -> tuple:
    try:
        r = subprocess.run([_find_iptables()] + args, capture_output=True, text=True, timeout=5)
        return r.returncode, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, str(e)


def is_available() -> bool:
    """Checks whether iptables is available on the device."""
    return os.path.isfile(_find_iptables())


def is_enabled() -> bool:
    """Checks whether the Kill Switch chain is active and hooked into OUTPUT."""
    rc, _ = _run(["-C", "OUTPUT", "-j", CHAIN])
    return rc == 0


def enable(wg_iface: str, endpoint_ip: str, endpoint_port: int = 51820) -> bool:
    """
    Enables the Kill Switch.
    Creates the WG_KILL_SWITCH chain and hooks it into OUTPUT/FORWARD.
    endpoint_port: UDP port of the WireGuard server (from config, e.g. 428 for HideMe).
    Returns True on success.
    """
    if is_enabled():
        notifier._log_msg("info", "Kill Switch already active")
        return True

    # Create chain (ignore if already exists)
    _run(["-N", CHAIN])

    # Chain rules: allow loopback, WG interface, WG endpoint UDP, established
    rules = [
        ["-A", CHAIN, "-o", "lo", "-j", "RETURN"],
        ["-A", CHAIN, "-i", "lo", "-j", "RETURN"],
    ]
    if wg_iface:
        rules += [
            ["-A", CHAIN, "-o", wg_iface, "-j", "RETURN"],
            ["-A", CHAIN, "-i", wg_iface, "-j", "RETURN"],
        ]
    if endpoint_ip:
        rules.append(["-A", CHAIN, "-d", endpoint_ip, "-p", "udp",
                       "--dport", str(endpoint_port), "-j", "RETURN"])

    rules += [
        ["-A", CHAIN, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "RETURN"],
        ["-A", CHAIN, "-j", "REJECT"],
    ]

    for rule in rules:
        rc, err = _run(rule)
        if rc != 0:
            notifier._log_msg("error", f"Kill Switch rule failed: {err[:60]}")
            disable()
            return False

    # Hook chain into OUTPUT/FORWARD
    for hook in ("OUTPUT", "FORWARD"):
        rc, err = _run(["-I", hook, "1", "-j", CHAIN])
        if rc != 0:
            notifier._log_msg("error", f"Kill Switch hook {hook} failed: {err[:60]}")
            disable()
            return False

    notifier._log_msg("info", f"Kill Switch enabled (iface={wg_iface}, endpoint={endpoint_ip})")
    return True


def disable():
    """
    Disables the Kill Switch.
    Unhooks the chain and deletes it. Errors are ignored (idempotent).
    """
    for hook in ("OUTPUT", "FORWARD"):
        _run(["-D", hook, "-j", CHAIN])

    _run(["-F", CHAIN])
    _run(["-X", CHAIN])
    notifier._log_msg("info", "Kill Switch disabled")


def swap_server(new_iface: str, new_endpoint: str, old_iface: str, old_endpoint: str,
                new_port: int = 51820, old_port: int = 51820):
    """
    Atomically swaps Kill Switch rules when switching servers.
    No moment exists where arbitrary traffic can flow unfiltered.

    Sequence:
    1. Insert new endpoint UDP exception → handshake to new server can begin
    2. Remove old interface and endpoint rules
    3. Insert new interface rules
    4. Remove temp endpoint exception (covered by interface rule)

    Chain state during the swap:
    Before:       loopback, old_iface, old_endpoint UDP, ESTABLISHED, REJECT
    After step 1: + new_endpoint UDP
    After step 2: − old_iface, − old_endpoint → loopback + new_endpoint UDP + ESTABLISHED
    After step 3: + new_iface
    After step 4: loopback, new_iface, ESTABLISHED, REJECT (final state)
    """
    if not is_enabled():
        return

    # 1. Insert new endpoint exception BEFORE ESTABLISHED+REJECT (position 5)
    _run(["-I", CHAIN, "5", "-d", new_endpoint, "-p", "udp",
          "--dport", str(new_port), "-j", "RETURN"])

    # 2. Remove old rules (by spec, not by position)
    _run(["-D", CHAIN, "-o", old_iface, "-j", "RETURN"])
    _run(["-D", CHAIN, "-i", old_iface, "-j", "RETURN"])
    if old_endpoint:
        _run(["-D", CHAIN, "-d", old_endpoint, "-p", "udp",
              "--dport", str(old_port), "-j", "RETURN"])

    # 3. Insert new interface rules (after lo rules, positions 3+4)
    _run(["-I", CHAIN, "3", "-o", new_iface, "-j", "RETURN"])
    _run(["-I", CHAIN, "4", "-i", new_iface, "-j", "RETURN"])

    # 4. Remove temp endpoint exception (interface rule now covers the traffic)
    _run(["-D", CHAIN, "-d", new_endpoint, "-p", "udp",
          "--dport", str(new_port), "-j", "RETURN"])

    notifier._log_msg("info", f"Kill Switch: swapped {old_iface}→{new_iface} (leak-free)")
