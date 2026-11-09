FROM octomon-rig-base
# Every client the rig knows, in one image: NordVPN's app, consumer WARP,
# Tailscale, wg-quick and OpenVPN. Their daemons are all left resident while
# one tunnel at a time (or two) is connected, which is the shape of a laptop
# with several VPN clients installed and the one octomon's naming rules
# (bystanders, elimination, the sole running client) exist for.
RUN apt-get update && apt-get install -y --no-install-recommends gnupg lsb-release wireguard-tools iptables openvpn \
    && curl -fsSL https://repo.nordvpn.com/gpg/nordvpn_public.asc \
        | gpg --dearmor -o /usr/share/keyrings/nordvpn.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nordvpn.gpg] https://repo.nordvpn.com/deb/nordvpn/debian stable main" \
        > /etc/apt/sources.list.d/nordvpn.list \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/cloudflare-client.list \
    && curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).noarmor.gpg" \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/tailscale.list \
    && apt-get update && apt-get install -y --no-install-recommends nordvpn cloudflare-warp tailscale \
    && rm -rf /var/lib/apt/lists/*
# The same fixtures as clients/wireguard and clients/openvpn (copies: a
# docker build context cannot reach outside its directory).
COPY wg0.conf /etc/wireguard/wg0.conf
WORKDIR /etc/openvpn/rig
COPY client.ovpn ca.crt client.crt client.key ./
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 600 /etc/wireguard/wg0.conf && chmod 755 /usr/local/bin/vpn
