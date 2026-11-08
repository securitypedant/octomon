FROM octomon-rig-base
RUN apt-get update && apt-get install -y --no-install-recommends openvpn \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /etc/openvpn/rig
COPY client.ovpn ca.crt client.crt client.key ./
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 755 /usr/local/bin/vpn
