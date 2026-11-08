#!/bin/sh
# vpn connect <port> | reconnect <port> | disconnect
# The rig's OpenVPN server listens on 1194 (pool 10.8.0.0/24) and 1195
# (pool 10.9.0.0/24); reconnecting to the other port is "another server".
set -eu
cd /etc/openvpn/rig
case "$1" in
    connect)
        openvpn --config client.ovpn --remote ovpn-server "$2" --dev tun0 \
            --daemon rig-ovpn --log /var/log/openvpn.log --writepid /run/openvpn.pid
        ;;
    reconnect)
        "$0" disconnect; sleep 2; "$0" connect "$2"
        ;;
    disconnect)
        if [ -f /run/openvpn.pid ]; then
            kill "$(cat /run/openvpn.pid)" 2>/dev/null || true
            i=0; while [ -d "/proc/$(cat /run/openvpn.pid)" ] && [ $i -lt 10 ]; do sleep 1; i=$((i+1)); done
            rm -f /run/openvpn.pid
        fi
        ;;
    *) echo "usage: vpn connect|reconnect <port> | disconnect" >&2; exit 2 ;;
esac
