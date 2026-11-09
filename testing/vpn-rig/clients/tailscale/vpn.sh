#!/bin/sh
# vpn up | wg-connect | wg-reconnect | wg-disconnect | dns-on | disconnect
# Tailscale as a resident mesh client (tun device tailscale0, 100.x and
# fd7a:115c:a1e0:: addresses, only its own routes), with wg-quick beside it
# for the mixed case. `dns-on` lets Tailscale take over the system resolver
# (MagicDNS, 100.100.100.100), which is one of the signals octomon names
# clients by: the mixed case is then run again to show the resolver names
# Tailscale and not the WireGuard tunnel beside it. The auth key comes from
# /run/secrets/tailscale.authkey (run.sh mounts it); the node is ephemeral,
# so logging out removes it.
set -eu
daemon() {
    if ! pgrep -x tailscaled >/dev/null; then
        tailscaled --state=/var/lib/tailscale/tailscaled.state --tun=tailscale0 >/var/log/tailscaled.log 2>&1 &
        i=0; until tailscale status >/dev/null 2>&1 || tailscale status 2>&1 | grep -q 'Logged out\|NeedsLogin' || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    fi
}
up() {
    daemon
    tailscale up --auth-key="$(tr -d '[:space:]' < /run/secrets/tailscale.authkey)" \
        --hostname=octomon-rig --accept-dns=false --accept-routes=false
    i=0; until tailscale status --json | jq -e '.BackendState == "Running"' >/dev/null || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    tailscale status
}
case "$1" in
    up) up ;;
    wg-connect) wg-quick up wg0 ;;
    wg-reconnect) wg-quick down wg0 || true; sleep 1; wg-quick up wg0 ;;
    wg-disconnect) wg-quick down wg0 || true ;;
    dns-on) tailscale set --accept-dns=true; sleep 2; cat /etc/resolv.conf ;;
    disconnect) wg-quick down wg0 >/dev/null 2>&1 || true; tailscale logout >/dev/null 2>&1 || true ;;
    *) echo "usage: vpn up | wg-connect | wg-reconnect | wg-disconnect | dns-on | disconnect" >&2; exit 2 ;;
esac
