FROM octomon-rig-base
# No VPN client at all: a plain GRE tunnel to servers/gre, made with ip(8).
# octomon can only know it is a tunnel from the kernel's device type.
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 755 /usr/local/bin/vpn
