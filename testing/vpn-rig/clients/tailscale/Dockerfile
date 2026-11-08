FROM octomon-rig-base
# Tailscale from its apt repository, plus wg-quick for the mixed case: a
# resident mesh client beside a WireGuard tunnel to the rig's server.
RUN apt-get update && apt-get install -y --no-install-recommends gnupg lsb-release wireguard-tools iptables \
    && curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).noarmor.gpg" \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/tailscale.list \
    && apt-get update && apt-get install -y --no-install-recommends tailscale \
    && rm -rf /var/lib/apt/lists/*
COPY wg0.conf /etc/wireguard/wg0.conf
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 600 /etc/wireguard/wg0.conf && chmod 755 /usr/local/bin/vpn
