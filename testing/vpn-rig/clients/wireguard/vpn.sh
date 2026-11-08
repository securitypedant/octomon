#!/bin/sh
# vpn connect <wg0|wg1> | reconnect <wg0|wg1> | disconnect
# A kernel WireGuard device set up by wg-quick: fwmark policy routing, the
# main table's default route stays on eth0.
set -eu
case "$1" in
    connect) wg-quick up "$2" ;;
    reconnect) wg-quick down "$2"; sleep 2; wg-quick up "$2" ;;
    disconnect) for c in wg0 wg1; do ip link show "$c" >/dev/null 2>&1 && wg-quick down "$c"; done; true ;;
    *) echo "usage: vpn connect|reconnect <conf> | disconnect" >&2; exit 2 ;;
esac
