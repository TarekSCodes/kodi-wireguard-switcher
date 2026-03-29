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


def enable(wg_iface: str, endpoint_ip: str, endpoint_port: int = 51820) -> bool:
    """
    Aktiviert den Kill Switch.
    Legt die Chain WG_KILL_SWITCH an und hängt sie in OUTPUT/FORWARD ein.
    endpoint_port: UDP-Port des WireGuard-Servers (aus Config, z.B. 428 bei HideMe).
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


def swap_server(new_iface: str, new_endpoint: str, old_iface: str, old_endpoint: str,
                new_port: int = 51820, old_port: int = 51820):
    """
    Tauscht Kill-Switch-Regeln leckfrei beim Server-Wechsel.
    Kein Moment in dem beliebiger Traffic ungefiltert fließen kann.

    Ablauf:
    1. Neue Endpoint-UDP-Ausnahme einfügen → Handshake zum neuen Server kann beginnen
    2. Alte Interface- und Endpoint-Regeln entfernen
    3. Neue Interface-Regeln einfügen
    4. Temp Endpoint-Ausnahme entfernen (durch Interface-Regel abgedeckt)

    Chain-Zustand während des Tauschs:
    Vor:        loopback, old_iface, old_endpoint UDP, ESTABLISHED, REJECT
    Nach Schritt 1: + new_endpoint UDP
    Nach Schritt 2: − old_iface, − old_endpoint → loopback + new_endpoint UDP + ESTABLISHED
    Nach Schritt 3: + new_iface
    Nach Schritt 4: loopback, new_iface, ESTABLISHED, REJECT (Endzustand)
    """
    if not is_enabled():
        return

    # 1. Neue Endpoint-Ausnahme VOR ESTABLISHED+REJECT einfügen (Position 5)
    _run(["-I", CHAIN, "5", "-d", new_endpoint, "-p", "udp",
          "--dport", str(new_port), "-j", "RETURN"])

    # 2. Alte Regeln entfernen (nach Spec, nicht nach Position)
    _run(["-D", CHAIN, "-o", old_iface, "-j", "RETURN"])
    _run(["-D", CHAIN, "-i", old_iface, "-j", "RETURN"])
    if old_endpoint:
        _run(["-D", CHAIN, "-d", old_endpoint, "-p", "udp",
              "--dport", str(old_port), "-j", "RETURN"])

    # 3. Neue Interface-Regeln einfügen (nach lo-Regeln, Positionen 3+4)
    _run(["-I", CHAIN, "3", "-o", new_iface, "-j", "RETURN"])
    _run(["-I", CHAIN, "4", "-i", new_iface, "-j", "RETURN"])

    # 4. Temp Endpoint-Ausnahme entfernen (Interface-Regel deckt Traffic jetzt ab)
    _run(["-D", CHAIN, "-d", new_endpoint, "-p", "udp",
          "--dport", str(new_port), "-j", "RETURN"])

    notifier._log_msg("info", f"Kill Switch: Tausch {old_iface}→{new_iface} (leckfrei)")
