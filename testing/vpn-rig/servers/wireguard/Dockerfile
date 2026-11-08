FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY wg0.conf /etc/wireguard/wg0.conf
RUN chmod 600 /etc/wireguard/wg0.conf
# wg-quick needs the in-kernel device (Docker Desktop's kernel has it) and
# NET_ADMIN; compose grants both. Stay up until stopped.
CMD ["sh", "-c", "wg-quick up wg0 && exec sleep infinity"]
