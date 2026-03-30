Place WireGuard config files here.

Important filename rules:
- Max 15 characters (Linux interface name limit!)
- No spaces, no dots
- Letters, digits, and hyphens only
- Example: HideMe-DE.conf, HideMe-NL.conf, HideMe-PL.conf

Config format (HideMe portal: Account -> VPN Apps -> WireGuard):

    [Interface]
    PrivateKey = <private_key_base64>
    Address = 10.8.0.2/32
    DNS = 185.213.26.187

    [Peer]
    PublicKey = <server_public_key_base64>
    Endpoint = de-frankfurt.hideservers.net:51820
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25

The DNS line is essential: wg-quick down cleanly resets DNS.
PersistentKeepalive = 25 prevents NAT timeouts.

WARNING: These files contain private keys — NEVER commit them!
