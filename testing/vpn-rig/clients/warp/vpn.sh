#!/bin/sh
# vpn connect | reconnect | reregister | disconnect
# Cloudflare WARP's Linux client in consumer mode (no account): a tun device
# named CloudflareWARP. The daemon is started on the first call and left
# running; the device is registered once. --accept-tos stands in for the
# terms dialog the desktop clients show.
set -eu
WARP="warp-cli --accept-tos"
daemon() {
    if ! pgrep -x warp-svc >/dev/null; then
        /usr/bin/warp-svc >/var/log/warp-svc.log 2>&1 &
        i=0; until warp-cli status >/dev/null 2>&1 || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    fi
    if $WARP registration show 2>&1 | grep -q 'Missing registration'; then
        $WARP registration new
        $WARP mode warp >/dev/null 2>&1 || true
    fi
}
# warp-cli connect returns before the tunnel is up; wait for it to say so.
wait_connected() {
    i=0; until $WARP status 2>/dev/null | grep -q 'Connected' || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    $WARP status
}
case "$1" in
    connect) daemon; $WARP connect; wait_connected ;;
    reconnect) daemon; $WARP disconnect || true; sleep 2; $WARP connect; wait_connected ;;
    # A fresh device identity: new keys, new tunnel addresses, same place.
    reregister) daemon; $WARP disconnect || true; $WARP registration delete || true; sleep 1
        $WARP registration new; $WARP mode warp >/dev/null 2>&1 || true; $WARP connect; wait_connected ;;
    disconnect) $WARP disconnect >/dev/null 2>&1 || true ;;
    *) echo "usage: vpn connect|reconnect|reregister|disconnect" >&2; exit 2 ;;
esac
