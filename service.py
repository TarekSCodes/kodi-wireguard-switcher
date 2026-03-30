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
        # Restore keymap after deploy (if button_code is stored in state.json)
        keymap_manager.restore_from_state(self._addon_path, self._manager.get_state())

        self._manager.restore()
        tick = 0
        while not self.abortRequested():
            if self.waitForAbort(1):  # NEVER use time.sleep() in Kodi services!
                break
            tick += 1
            if tick >= 30:
                tick = 0
                self._manager.auto_reconnect()
        # Do NOT tear down the tunnel on Kodi shutdown — stays active at OS level


if __name__ == "__main__":
    WireGuardService().run()
