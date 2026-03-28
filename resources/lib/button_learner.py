import xbmc
import xbmcgui

_ACTION_PREVIOUS_MENU = 10
_ACTION_NAV_BACK = 92


class ButtonLearnerWindow(xbmcgui.WindowDialog):
    """
    Vollbild-Overlay das auf den nächsten Fernbedienungsdruck wartet
    und dessen Button-Code zurückgibt.
    """

    def __init__(self):
        super().__init__()
        self._button_code = None
        self._cancelled = False
        self._build_ui()

    def _build_ui(self):
        # Kodi-Koordinatensystem: immer 1920x1080
        w, h = 860, 300
        x = (1920 - w) // 2
        y = (1080 - h) // 2

        self.addControl(xbmcgui.ControlLabel(
            x, y + 20, w, 60,
            "WireGuard — Taste belegen",
            font="font20",
            textColor="0xFFFFFFFF",
            alignment=0x00000002,  # XBFONT_CENTER_X
        ))
        self.addControl(xbmcgui.ControlLabel(
            x + 40, y + 110, w - 80, 100,
            "Drücke die Taste auf deiner Fernbedienung,\n"
            "die du für den VPN-Wechsel verwenden möchtest.",
            font="font16",
            textColor="0xFFCCCCCC",
            alignment=0x00000002,
        ))
        self.addControl(xbmcgui.ControlLabel(
            x, y + 245, w, 36,
            "[Zurück / ESC = Abbrechen]",
            font="font13",
            textColor="0xFF888888",
            alignment=0x00000002,
        ))

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
