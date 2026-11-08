FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        openvpn iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /etc/openvpn/rig
COPY ca.crt server.crt server.key server.conf server2.conf ./
# Two servers with two pools, so a reconnect can land on a new address.
# Both NAT their pool out of eth0, so a full tunnel reaches the internet.
CMD ["sh", "-c", "\
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE && \
    iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE && \
    openvpn --config server2.conf --daemon ovpn2 --log /var/log/openvpn2.log && \
    exec openvpn --config server.conf"]
