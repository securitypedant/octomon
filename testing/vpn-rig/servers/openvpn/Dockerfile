FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        openvpn iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /etc/openvpn/rig
COPY ca.crt server.crt server.key server.conf server2.conf ./
# Two servers with two pools, so a reconnect can land on a new address.
# Both NAT their pool out of eth0, so a full tunnel reaches the internet.
# TCP checksums are recomputed on the way into each tunnel (see csum.sh):
# replies from Docker Desktop's NAT arrive over the veth with their checksum
# unfilled, and forwarded into a tun device as-is they are dropped by the
# client's kernel. Ping works, web does not: octomon reports exactly that,
# so without this the rig blames the client for the rig's own plumbing.
COPY csum.sh /usr/local/bin/rig-csum
CMD ["sh", "-c", "\
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE && \
    iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE && \
    openvpn --config server2.conf --daemon ovpn2 --log /var/log/openvpn2.log --up /usr/local/bin/rig-csum --script-security 2 && \
    exec openvpn --config server.conf --up /usr/local/bin/rig-csum --script-security 2"]
