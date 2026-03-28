import xbmcaddon
import xbmcgui
import xbmcvfs

_ACTION_PREVIOUS_MENU = 10
_ACTION_NAV_BACK = 92


class ButtonLearnerWindow(xbmcgui.WindowXMLDialog):
    """
    Nativer Kodi-Dialog der auf den nächsten Fernbedienungsdruck wartet
    und dessen Button-Code zurückgibt.
    """

    def __new__(cls):
        addon_path = xbmcvfs.translatePath(xbmcaddon.Addon().getAddonInfo("path"))
        return super().__new__(cls, "DialogButtonLearner.xml", addon_path, "Default", "720p")

    def __init__(self):
        super().__init__()
        self._button_code = None
        self._cancelled = False

    def onAction(self, action):
        action_id = action.getId()
        if action_id in (_ACTION_PREVIOUS_MENU, _ACTION_NAV_BACK):
            self._cancelled = True
            self.close()
            return
        code = action.getButtonCode()
        if code != 0:
            self._button_code = code
            self.close()

    def get_result(self):
        """Gibt den Button-Code zurück, oder None wenn abgebrochen."""
        return None if self._cancelled else self._button_code
