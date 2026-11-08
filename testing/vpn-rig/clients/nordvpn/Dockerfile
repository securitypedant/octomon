FROM octomon-rig-base
# NordVPN's own Linux client, from its apt repository. nordvpnd normally runs
# under systemd; the rig starts it by hand (see vpn.sh).
RUN apt-get update && apt-get install -y --no-install-recommends gnupg \
    && curl -fsSL https://repo.nordvpn.com/gpg/nordvpn_public.asc \
        | gpg --dearmor -o /usr/share/keyrings/nordvpn.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nordvpn.gpg] https://repo.nordvpn.com/deb/nordvpn/debian stable main" \
        > /etc/apt/sources.list.d/nordvpn.list \
    && apt-get update && apt-get install -y --no-install-recommends nordvpn \
    && rm -rf /var/lib/apt/lists/*
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 755 /usr/local/bin/vpn
