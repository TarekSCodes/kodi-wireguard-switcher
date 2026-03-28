ADDON_NAME = "WireGuard"

try:
    import xbmc
    import xbmcgui
    _IN_KODI = True
except ImportError:
    import logging
    _log = logging.getLogger("wg_switcher")
    _IN_KODI = False


def _log_msg(level, msg):
    if _IN_KODI:
        level_map = {
            "info": xbmc.LOGINFO,
            "warning": xbmc.LOGWARNING,
            "error": xbmc.LOGERROR,
        }
        xbmc.log(f"[WireGuardSwitcher] {msg}", level_map.get(level, xbmc.LOGINFO))
    else:
        getattr(_log, level, _log.info)(msg)


def _notify(message, icon, duration):
    if _IN_KODI:
        xbmcgui.Dialog().notification(ADDON_NAME, message, icon, duration)
    else:
        _log_msg("info", f"NOTIFY: {message}")


def connecting(server_name: str):
    _log_msg("info", f"Connecting to {server_name}...")
    _notify(f"Connecting: {server_name}", xbmcgui.NOTIFICATION_INFO if _IN_KODI else "", 5000)


def connected(server_name: str):
    _log_msg("info", f"Connected to {server_name}")
    _notify(f"Connected: {server_name}", xbmcgui.NOTIFICATION_INFO if _IN_KODI else "", 4000)


def disconnected(server_name: str):
    _log_msg("warning", f"Disconnected from {server_name}")
    _notify(f"Disconnected: {server_name}", xbmcgui.NOTIFICATION_WARNING if _IN_KODI else "", 3000)


def error(detail: str):
    _log_msg("error", f"Error: {detail}")
    _notify(f"Error: {detail}", xbmcgui.NOTIFICATION_ERROR if _IN_KODI else "", 5000)


def reconnecting(server_name: str):
    _log_msg("warning", f"Tunnel down, reconnecting to {server_name}...")
    _notify(f"Reconnecting: {server_name}", xbmcgui.NOTIFICATION_WARNING if _IN_KODI else "", 3000)


def kill_switch_blocking():
    _log_msg("error", "Kill Switch aktiv — kein Internet, VPN getrennt")
    # Dauer 35000ms: überbrückt den 30s-Reconnect-Zyklus, bleibt also dauerhaft sichtbar
    # bis der Tunnel wieder steht und eine "Connected"-Meldung sie ablöst
    _notify(
        "Kein Internet — VPN getrennt (Kill Switch)",
        xbmcgui.NOTIFICATION_ERROR if _IN_KODI else "",
        35000,
    )
