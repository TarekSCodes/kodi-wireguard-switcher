import os

import xbmc


def write_keymap(addon_path: str, button_code: int = None):
    """
    Schreibt keymaps/wireguard.xml.
    button_code: Wenn gesetzt, wird ein <key id="..."> für die Fernbedienung eingetragen.
    Danach lädt Kodi die Keymaps automatisch neu.
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

    keymap_path = os.path.join(addon_path, "keymaps", "wireguard.xml")
    with open(keymap_path, "w", encoding="utf-8") as f:
        f.write(xml)

    xbmc.executebuiltin("Action(reloadkeymaps)")
    xbmc.log(f"[WireGuardSwitcher] Keymap geschrieben (button_code={button_code})", xbmc.LOGINFO)


def restore_from_state(addon_path: str, state: dict):
    """Stellt die Keymap aus dem gespeicherten State wieder her (nach Deploy)."""
    button_code = state.get("button_code")
    if button_code is not None:
        write_keymap(addon_path, button_code=int(button_code))
