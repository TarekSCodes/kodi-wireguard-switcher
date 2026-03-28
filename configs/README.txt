WireGuard Config-Dateien hier ablegen.

Wichtige Regeln fuer Dateinamen:
- Max 15 Zeichen (Linux-Interface-Name-Limit!)
- Keine Leerzeichen, keine Punkte
- Nur Buchstaben, Ziffern, Bindestriche
- Beispiel: HideMe-DE.conf, HideMe-NL.conf, HideMe-PL.conf

Config-Format (HideMe-Portal: Konto -> VPN Apps -> WireGuard):

    [Interface]
    PrivateKey = <private_key_base64>
    Address = 10.8.0.2/32
    DNS = 185.213.26.187

    [Peer]
    PublicKey = <server_public_key_base64>
    Endpoint = de-frankfurt.hideservers.net:51820
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25

Die DNS-Zeile ist entscheidend: wg-quick down setzt DNS sauber zurueck.
PersistentKeepalive = 25 verhindert NAT-Timeouts.

ACHTUNG: Diese Dateien enthalten Private Keys — NIEMALS committen!
