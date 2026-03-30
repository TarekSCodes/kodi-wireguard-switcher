import xbmcaddon
import xbmcgui
import xbmcvfs

_ACTION_PREVIOUS_MENU = 10
_ACTION_NAV_BACK = 92


class ButtonLearnerWindow(xbmcgui.WindowXMLDialog):
    """
    Native Kodi dialog that waits for the next remote button press
    and returns its button code.
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
        """Returns the button code, or None if cancelled."""
        return None if self._cancelled else self._button_code
