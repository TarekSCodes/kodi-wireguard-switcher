"""
Kodi-Module als Stubs registrieren, damit die Addon-Dateien ohne Kodi importierbar sind.
"""
import sys
from unittest.mock import MagicMock

# Kodi-Stubs
for mod in ("xbmc", "xbmcaddon", "xbmcgui", "xbmcvfs"):
    sys.modules[mod] = MagicMock()

# xbmcvfs.translatePath gibt den Pfad unverändert zurück
import xbmcvfs
xbmcvfs.translatePath.side_effect = lambda p: p
