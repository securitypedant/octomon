#!/bin/sh
# vpn daemons | none | nord | warp | both | wg | ovpn | disconnect
# One container with every client installed and every daemon resident
# (nordvpnd, warp-svc, tailscaled), the way a laptop with several VPN apps
# looks to octomon. Each command first brings every tunnel down, then
# connects the one it names (or two), so phases are independent of their
# order. nordvpnd needs /run/secrets/nordvpn.token and tailscaled
# /run/secrets/tailscale.authkey; a daemon whose secret is absent is simply
# not started, and expect.json marks the phases that need it.
set -eu
WARP="warp-cli --accept-tos"
wait_for() { # <seconds> <command...>: poll until the command succeeds
    n=$1; shift; i=0
    until "$@" >/dev/null 2>&1 || [ $i -ge "$n" ]; do sleep 1; i=$((i+1)); done
}
nord_daemon() {
    [ -f /run/secrets/nordvpn.token ] || return 0
    if ! pgrep -x nordvpnd >/dev/null; then
        /usr/sbin/nordvpnd >/var/log/nordvpnd.log 2>&1 &
        wait_for 30 nordvpn version
    fi
    # `nordvpn account` also fails with "Something went wrong" while the
    # daemon is unsettled after another client's attempt; only a clear "not
    # logged in" means a login is due.
    if nordvpn account 2>&1 | grep -qi 'not logged in'; then
        nordvpn login --token "$(tr -d '[:space:]' < /run/secrets/nordvpn.token)"
        nordvpn set protocol nordlynx >/dev/null 2>&1 || true
        nordvpn set analytics off >/dev/null 2>&1 || true
        nordvpn set firewall off >/dev/null 2>&1 || true
    fi
}
warp_daemon() {
    if ! pgrep -x warp-svc >/dev/null; then
        /usr/bin/warp-svc >/var/log/warp-svc.log 2>&1 &
        wait_for 30 warp-cli status
    fi
    if $WARP registration show 2>&1 | grep -q 'Missing registration'; then
        $WARP registration new
        $WARP mode warp >/dev/null 2>&1 || true
    fi
}
ts_daemon() {
    [ -f /run/secrets/tailscale.authkey ] || return 0
    if ! pgrep -x tailscaled >/dev/null; then
        tailscaled --state=/var/lib/tailscale/tailscaled.state --tun=tailscale0 >/var/log/tailscaled.log 2>&1 &
        sleep 3
        tailscale up --auth-key="$(tr -d '[:space:]' < /run/secrets/tailscale.authkey)" \
            --hostname=octomon-rig-crowded --accept-dns=false --accept-routes=false
        i=0; until tailscale status --json | jq -e '.BackendState == "Running"' >/dev/null || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
    fi
}
daemons() { nord_daemon; warp_daemon; ts_daemon; }
warp_connected() { $WARP status 2>/dev/null | grep -q 'Status update: Connected'; }
warp_disconnected() { $WARP status 2>/dev/null | grep -q 'Status update: Disconnected'; }
nord_disconnected() { ! pgrep -x nordvpnd >/dev/null || nordvpn status 2>/dev/null | grep -q 'Status: Disconnected'; }
lan_dns() { getent hosts wg-server >/dev/null 2>&1; }
# Every tunnel down, and the daemons settled: each of them rewrites
# /etc/resolv.conf while it is up, and NordVPN's stays behind until the
# daemon reports Disconnected, so the next client's endpoint lookup would
# hang on resolvers that are no longer reachable.
none() {
    nordvpn disconnect >/dev/null 2>&1 || true
    $WARP disconnect >/dev/null 2>&1 || true
    wg-quick down wg0 >/dev/null 2>&1 || true
    if [ -f /run/openvpn.pid ]; then
        kill "$(cat /run/openvpn.pid)" 2>/dev/null || true; rm -f /run/openvpn.pid
    fi
    wait_for 20 nord_disconnected
    wait_for 20 warp_disconnected
    wait_for 20 lan_dns
    sleep 2
}
nord() { nordvpn connect; }
warp() { $WARP connect; wait_for 40 warp_connected; $WARP status; }
wg() { wg-quick up wg0; }
ovpn() {
    cd /etc/openvpn/rig && openvpn --config client.ovpn --remote ovpn-server 1194 --dev tun0 \
        --daemon rig-ovpn --log /var/log/openvpn.log --writepid /run/openvpn.pid
}
case "$1" in
    daemons) daemons; pgrep -l 'nordvpnd|warp-svc|tailscaled' ;;
    none) daemons; none ;;
    nord) daemons; none; nord ;;
    warp) daemons; none; warp ;;
    wg) daemons; none; wg ;;
    ovpn) daemons; none; ovpn ;;
    # Two tunnels at once. WARP connects over a wg-quick tunnel and carries
    # the traffic from then on; the WireGuard device stays up beside it.
    wg+warp) daemons; none; wg; warp ;;
    # NordVPN beside WARP does not work on Linux: once nordlynx is up, WARP's
    # own connection to Cloudflare dies in Nord's routing and the client
    # gives up ("Unable"), so what octomon sees is NordVPN alone. The phase
    # records that; the probe runs whatever WARP ended up doing.
    nord+warp) daemons; none; nord; $WARP connect || true; wait_for 40 warp_connected || true; $WARP status ;;
    disconnect) none; tailscale logout >/dev/null 2>&1 || true ;;
    *) echo "usage: vpn daemons|none|nord|warp|wg|ovpn|wg+warp|nord+warp|disconnect" >&2; exit 2 ;;
esac
