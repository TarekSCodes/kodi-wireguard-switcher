import xbmc
import xbmcaddon
import xbmcvfs

from resources.lib import keymap_manager
from resources.lib.wg_manager import WireGuardManager


def get_addon_path() -> str:
    return xbmcvfs.translatePath(xbmcaddon.Addon().getAddonInfo("path"))


class WireGuardService(xbmc.Monitor):
    def __init__(self):
        super().__init__()
        self._addon_path = get_addon_path()
        self._manager = WireGuardManager(self._addon_path)

    def run(self):
        # Keymap nach Deploy wiederherstellen (falls button_code in state.json gespeichert)
        keymap_manager.restore_from_state(self._addon_path, self._manager.get_state())

        self._manager.restore()
        tick = 0
        while not self.abortRequested():
            if self.waitForAbort(1):  # NIEMALS time.sleep() in Kodi-Services!
                break
            tick += 1
            if tick >= 30:
                tick = 0
                self._manager.auto_reconnect()
        # Tunnel beim Kodi-Shutdown NICHT trennen — bleibt auf OS-Ebene aktiv


if __name__ == "__main__":
    WireGuardService().run()
