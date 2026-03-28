import os

import xbmc
import xbmcvfs

KEYMAP_FILENAME = "wireguard.xml"


def _keymap_path() -> str:
    return xbmcvfs.translatePath(f"special://userdata/keymaps/{KEYMAP_FILENAME}")


def write_keymap(addon_path: str, button_code: int = None):
    """
    Schreibt die Keymap nach special://userdata/keymaps/wireguard.xml.
    Diese Location wird von Kodi dynamisch neu geladen (Action(reloadkeymaps)).
    ZIP-install-safe: service.py ruft diese Funktion beim Start auf.

    button_code: Wenn gesetzt, wird ein <key id="..."> für die Fernbedienung
    in den <keyboard>-Abschnitt eingetragen (NICHT <remote> — remote kennt
    keine numerischen IDs, keyboard schon).
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
    xbmc.log(f"[WireGuardSwitcher] Keymap geschrieben nach {keymap_path} (button_code={button_code})", xbmc.LOGINFO)


def find_key_conflict(button_code: int) -> str | None:
    """
    Prüft ob eine andere Keymap-Datei denselben key id bereits belegt.
    Gibt den Dateinamen zurück (nur Name, nicht Pfad) oder None.
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
    Entfernt alle Vorkommen von <key id="button_code"> aus einer Keymap-Datei.
    Schreibt die bereinigte Version zurück.
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
        xbmc.log(f"[WireGuardSwitcher] key id={button_code} aus {fname} entfernt", xbmc.LOGINFO)
    except OSError as e:
        xbmc.log(f"[WireGuardSwitcher] Konnte {fname} nicht bereinigen: {e}", xbmc.LOGWARNING)


def restore_from_state(addon_path: str, state: dict):
    """Stellt die Keymap aus dem gespeicherten State wieder her (nach Deploy / Kodi-Start)."""
    button_code = state.get("button_code")
    write_keymap(addon_path, button_code=int(button_code) if button_code is not None else None)
