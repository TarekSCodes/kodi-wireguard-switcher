import sys
import urllib.request

import xbmcaddon
import xbmcgui
import xbmcvfs

from resources.lib import keymap_manager
from resources.lib import notifier
from resources.lib.button_learner import ButtonLearnerWindow
from resources.lib.wg_manager import WireGuardManager


def get_addon_path() -> str:
    return xbmcvfs.translatePath(xbmcaddon.Addon().getAddonInfo("path"))


def learn_button(addon_path: str):
    win = ButtonLearnerWindow()
    win.doModal()
    code = win.get_result()
    del win

    if code is None:
        notifier._log_msg("info", "Button-Lernen abgebrochen")
        return

    notifier._log_msg("info", f"Button-Code gelernt: {code}")

    manager = WireGuardManager(addon_path)
    manager.set_button_code(code)
    keymap_manager.write_keymap(addon_path, button_code=code)

    xbmcgui.Dialog().ok(
        "WireGuard Switcher",
        "Taste erfolgreich gespeichert!\n\nAb sofort wechselt diese Taste den VPN-Server."
    )


def show_status(addon_path: str):
    from resources.lib import kill_switch as ks
    manager = WireGuardManager(addon_path)
    server = manager.get_state().get("current_server") or "—"
    tunnel_up = manager.is_tunnel_up()
    ks_active = ks.is_enabled()

    if tunnel_up:
        status = "Verbunden"
    elif ks_active:
        status = "Getrennt  ⚠ Kill Switch blockiert Internet!"
    else:
        status = "Nicht verbunden"

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            current_ip = resp.read().decode().strip()
    except Exception:
        current_ip = "(nicht abrufbar — Kill Switch aktiv?)" if ks_active else "(nicht abrufbar)"

    if tunnel_up:
        ip_label = f"VPN-Exit-IP:  {current_ip}"
    else:
        ip_label = f"Eigene IP:    {current_ip}  ⚠ Kein VPN aktiv!"

    xbmcgui.Dialog().ok(
        "WireGuard Status",
        f"Server:    {server}\nStatus:    {status}\n{ip_label}"
    )


if __name__ == "__main__":
    addon_path = get_addon_path()
    try:
        arg = sys.argv[1] if len(sys.argv) > 1 else ""
        if arg == "learn":
            learn_button(addon_path)
        elif arg == "status":
            show_status(addon_path)
        elif arg == "next":
            WireGuardManager(addon_path).cycle_next()
        else:
            WireGuardManager(addon_path).cycle_next()
    except Exception as e:
        notifier.error(str(e)[:80])
