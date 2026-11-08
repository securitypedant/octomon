#!/bin/sh
# vpn connect [country] | reconnect [country] | disconnect
# NordVPN's CLI over NordLynx: a kernel WireGuard device named nordlynx at
# 10.5.0.x. The token comes from /run/secrets/nordvpn.token (run.sh mounts
# it). The daemon is started on the first call and left running.
set -eu
daemon() {
    if ! pgrep -x nordvpnd >/dev/null; then
        /usr/sbin/nordvpnd >/var/log/nordvpnd.log 2>&1 &
        i=0; until nordvpn version >/dev/null 2>&1 || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    fi
    if ! nordvpn account >/dev/null 2>&1; then
        nordvpn login --token "$(tr -d '[:space:]' < /run/secrets/nordvpn.token)"
        nordvpn set protocol nordlynx >/dev/null 2>&1 || true
        nordvpn set analytics off >/dev/null 2>&1 || true
        nordvpn set firewall off >/dev/null 2>&1 || true
    fi
}
case "$1" in
    connect) daemon; nordvpn connect ${2:-} ;;
    reconnect) daemon; nordvpn disconnect || true; sleep 2; nordvpn connect ${2:-} ;;
    disconnect) nordvpn disconnect >/dev/null 2>&1 || true ;;
    *) echo "usage: vpn connect|reconnect [country] | disconnect" >&2; exit 2 ;;
esac
