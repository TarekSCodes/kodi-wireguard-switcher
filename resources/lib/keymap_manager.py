import os

import xbmc
import xbmcvfs

KEYMAP_FILENAME = "wireguard.xml"


def _keymap_path() -> str:
    return xbmcvfs.translatePath(f"special://userdata/keymaps/{KEYMAP_FILENAME}")


def write_keymap(addon_path: str, button_code: int = None):
    """
    Writes the keymap to special://userdata/keymaps/wireguard.xml.
    This location is dynamically reloaded by Kodi (Action(reloadkeymaps)).
    ZIP-install-safe: service.py calls this function on startup.

    button_code: If set, a <key id="..."> for the remote is added to the
    <keyboard> section (NOT <remote> — remote does not support numeric IDs,
    keyboard does).
    """
    key_line = ""
    if button_code is not None:
        key_line = f'      <key id="{button_code}">RunScript(service.wireguard.switcher)</key>\n'

    xml = (
        "<keymap>\n"
        "  <global>\n"
        "    <keyboard>\n"
        "      <w>RunScript(service.wireguard.switcher)</w>\n"
        + key_line +
        "    </keyboard>\n"
        "  </global>\n"
        "</keymap>\n"
    )

    keymap_path = _keymap_path()
    with open(keymap_path, "w", encoding="utf-8") as f:
        f.write(xml)

    xbmc.executebuiltin("Action(reloadkeymaps)")
    xbmc.log(f"[WireGuardSwitcher] Keymap written to {keymap_path} (button_code={button_code})", xbmc.LOGINFO)


def find_key_conflict(button_code: int) -> str | None:
    """
    Checks whether another keymap file already uses the same key id.
    Returns the filename (name only, not path) or None.
    """
    keymap_dir = xbmcvfs.translatePath("special://userdata/keymaps/")
    try:
        entries = os.listdir(keymap_dir)
    except OSError:
        return None

    for fname in entries:
        if fname == KEYMAP_FILENAME or not fname.endswith(".xml"):
            continue
        path = os.path.join(keymap_dir, fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if f'id="{button_code}"' in content or f"id='{button_code}'" in content:
                return fname
        except OSError:
            pass
    return None


def remove_key_from_file(fname: str, button_code: int):
    """
    Removes all occurrences of <key id="button_code"> from a keymap file.
    Writes the cleaned version back.
    """
    keymap_dir = xbmcvfs.translatePath("special://userdata/keymaps/")
    path = os.path.join(keymap_dir, fname)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        cleaned = [
            line for line in lines
            if f'id="{button_code}"' not in line and f"id='{button_code}'" not in line
        ]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(cleaned)
        xbmc.log(f"[WireGuardSwitcher] key id={button_code} removed from {fname}", xbmc.LOGINFO)
    except OSError as e:
        xbmc.log(f"[WireGuardSwitcher] Could not clean {fname}: {e}", xbmc.LOGWARNING)


def restore_from_state(addon_path: str, state: dict):
    """Restores the keymap from the saved state (after deploy / Kodi startup)."""
    button_code = state.get("button_code")
    write_keymap(addon_path, button_code=int(button_code) if button_code is not None else None)
