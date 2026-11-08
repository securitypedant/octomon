FROM octomon-rig-base
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iptables \
    && rm -rf /var/lib/apt/lists/*
COPY wg0.conf wg1.conf /etc/wireguard/
RUN chmod 600 /etc/wireguard/*.conf
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 755 /usr/local/bin/vpn
