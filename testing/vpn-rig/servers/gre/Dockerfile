FROM ubuntu:24.04
# The far end of a plain GRE tunnel: no VPN software, no vendor, just a
# kernel tunnel device and NAT out to the LAN. Addresses are fixed because
# GRE needs to know its peer (see compose.yml and clients/unnamed). TCP
# checksums are recomputed on the way into the tunnel for the reason given
# in servers/openvpn/Dockerfile.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
CMD set -e; \
    ip link add gre1 type gre local 172.30.0.250 remote 172.30.0.200 ttl 64; \
    ip addr add 10.77.0.1/24 dev gre1; ip link set gre1 up; \
    iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE; \
    tc qdisc add dev gre1 root handle 1: prio; \
    tc filter add dev gre1 parent 1: protocol ip u32 match ip protocol 6 0xff action csum ip tcp; \
    exec sleep infinity
