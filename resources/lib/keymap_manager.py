import os

import xbmc
import xbmcvfs


def write_keymap(addon_path: str, button_code: int = None):
    """
    Schreibt die Keymap nach special://userdata/keymaps/wireguard.xml.
    Diese Location wird von Kodi dynamisch neu geladen (Action(reloadkeymaps)).
    ZIP-install-safe: service.py ruft diese Funktion beim Start auf.

    button_code: Wenn gesetzt, wird ein <key id="..."> für die Fernbedienung eingetragen.
    """
    remote_block = ""
    if button_code is not None:
        remote_block = (
            "    <remote>\n"
            f'      <key id="{button_code}">RunScript(service.wireguard.switcher)</key>\n'
            "    </remote>\n"
        )

    xml = (
        "<keymap>\n"
        "  <global>\n"
        "    <keyboard>\n"
        "      <w>RunScript(service.wireguard.switcher)</w>\n"
        "    </keyboard>\n"
        + remote_block +
        "  </global>\n"
        "</keymap>\n"
    )

    keymap_path = xbmcvfs.translatePath("special://userdata/keymaps/wireguard.xml")
    with open(keymap_path, "w", encoding="utf-8") as f:
        f.write(xml)

    xbmc.executebuiltin("Action(reloadkeymaps)")
    xbmc.log(f"[WireGuardSwitcher] Keymap geschrieben nach {keymap_path} (button_code={button_code})", xbmc.LOGINFO)


def restore_from_state(addon_path: str, state: dict):
    """Stellt die Keymap aus dem gespeicherten State wieder her (nach Deploy / Kodi-Start)."""
    button_code = state.get("button_code")
    write_keymap(addon_path, button_code=int(button_code) if button_code is not None else None)
