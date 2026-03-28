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
    """Prüft ob iptables auf dem Gerät verfügbar ist."""
    return os.path.isfile(_find_iptables())


def is_enabled() -> bool:
    """Prüft ob die Kill-Switch-Chain aktiv in OUTPUT eingehängt ist."""
    rc, _ = _run(["-C", "OUTPUT", "-j", CHAIN])
    return rc == 0


def enable(wg_iface: str, endpoint_ip: str) -> bool:
    """
    Aktiviert den Kill Switch.
    Legt die Chain WG_KILL_SWITCH an und hängt sie in OUTPUT/INPUT/FORWARD ein.
    Gibt True zurück wenn erfolgreich.
    """
    if is_enabled():
        notifier._log_msg("info", "Kill Switch bereits aktiv")
        return True

    # Chain anlegen (ignorieren falls schon vorhanden)
    _run(["-N", CHAIN])

    # Regeln in der Chain: erlaubt werden loopback, WG-Interface, WG-Endpoint-UDP, established
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
        rules.append(["-A", CHAIN, "-d", endpoint_ip, "-p", "udp", "--dport", "51820", "-j", "RETURN"])

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

    # Chain in OUTPUT/INPUT/FORWARD einhängen
    for hook in ("OUTPUT", "FORWARD"):
        rc, err = _run(["-I", hook, "1", "-j", CHAIN])
        if rc != 0:
            notifier._log_msg("error", f"Kill Switch hook {hook} failed: {err[:60]}")
            disable()
            return False

    notifier._log_msg("info", f"Kill Switch aktiviert (iface={wg_iface}, endpoint={endpoint_ip})")
    return True


def disable():
    """
    Deaktiviert den Kill Switch.
    Hängt die Chain aus und löscht sie. Fehler werden ignoriert (idempotent).
    """
    for hook in ("OUTPUT", "FORWARD"):
        _run(["-D", hook, "-j", CHAIN])

    _run(["-F", CHAIN])
    _run(["-X", CHAIN])
    notifier._log_msg("info", "Kill Switch deaktiviert")
