FROM octomon-rig-base
# No VPN: this client breaks its own network on purpose (tc netem, iptables)
# and the rig checks what octomon's analysis says about each break. busybox
# provides the tiny web server the captive-portal phase answers with.
RUN apt-get update && apt-get install -y --no-install-recommends iptables busybox \
    && rm -rf /var/lib/apt/lists/*
COPY portal.html /srv/portal/index.html
COPY vpn.sh /usr/local/bin/vpn
RUN chmod 755 /usr/local/bin/vpn
