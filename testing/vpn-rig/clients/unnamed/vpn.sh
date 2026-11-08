#!/bin/sh
# vpn connect <inner-addr> | reconnect <inner-addr> | disconnect
# A full tunnel over plain GRE: gre1 to the rig's GRE peer, default route
# through it, the peer itself still reached on the LAN. Nothing names it.
# Never use `type ipip` here: Docker Desktop's kernel (7.0.14-linuxkit)
# oopses in ipip_newlink and takes the whole VM down.
set -eu
PEER=172.30.0.250
up() {
    ip link add gre1 type gre local "$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)" remote $PEER ttl 64
    ip addr add "$1" dev gre1
    ip link set gre1 up
    # Take the internet over the way most clients do (OpenVPN's def1, WARP):
    # two half-routes over the LAN default, which stays in place.
    ip route add 0.0.0.0/1 dev gre1
    ip route add 128.0.0.0/1 dev gre1
}
down() {
    ip link del gre1 2>/dev/null || true
}
case "$1" in
    connect) up "${2:-10.77.0.2/24}" ;;
    reconnect) down; sleep 1; up "${2:-10.77.0.6/24}" ;;
    disconnect) down ;;
    *) echo "usage: vpn connect|reconnect [addr/len] | disconnect" >&2; exit 2 ;;
esac
