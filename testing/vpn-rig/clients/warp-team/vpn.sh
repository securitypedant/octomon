#!/bin/sh
# vpn connect | reconnect | reregister | no-v6 | disconnect
# Cloudflare WARP's Linux client enrolled in a Zero Trust organisation with a
# service token, read from /run/secrets/warp-team.env (WARP_ORG,
# WARP_CLIENT_ID, WARP_CLIENT_SECRET) and written to the client's managed
# configuration, /var/lib/cloudflare-warp/mdm.xml, before the daemon starts:
# with that file in place warp-svc registers the device itself, no browser,
# and registers again on its own if the registration is deleted. The tunnel
# protocol is the organisation's setting (`warp-cli tunnel protocol` is
# consumer-only), and so is the interface address: 172.16.0.2 under
# WireGuard unless "assign a unique IP address to each device" is on, the
# device's own 100.96/12 address under MASQUE or with that setting on. The
# probe records which one the org handed out.
set -eu
WARP="warp-cli --accept-tos"
MDM=/var/lib/cloudflare-warp/mdm.xml
enrol() {
    [ -f "$MDM" ] && return
    # shellcheck disable=SC1091
    . /run/secrets/warp-team.env
    : "${WARP_ORG:?}" "${WARP_CLIENT_ID:?}" "${WARP_CLIENT_SECRET:?}"
    mkdir -p "$(dirname "$MDM")"
    umask 077
    cat >"$MDM" <<XML
<dict>
  <key>organization</key>
  <string>$WARP_ORG</string>
  <key>auth_client_id</key>
  <string>$WARP_CLIENT_ID</string>
  <key>auth_client_secret</key>
  <string>$WARP_CLIENT_SECRET</string>
  <key>service_mode</key>
  <string>warp</string>
  <key>onboarding</key>
  <false/>
</dict>
XML
}
registered() { $WARP registration show 2>/dev/null | grep -q '^Organization'; }
svc_up() { warp-cli status >/dev/null 2>&1; }
connected() { $WARP status 2>/dev/null | grep -q 'Status update: Connected'; }
wait_for() { # <seconds> <command...>
    n=$1; shift; i=0
    until "$@" || [ $i -ge "$n" ]; do sleep 1; i=$((i+1)); done
}
daemon() {
    enrol
    if ! pgrep -x warp-svc >/dev/null; then
        /usr/bin/warp-svc >/var/log/warp-svc.log 2>&1 &
        wait_for 30 svc_up
    fi
    # Registration from mdm.xml takes a moment after the daemon is up.
    wait_for 30 registered
    $WARP registration show | grep -E '^(Device ID|Organization)' || true
}
wait_connected() { wait_for 45 connected; $WARP status; }
case "$1" in
    connect) daemon; $WARP connect; wait_connected ;;
    reconnect) daemon; $WARP disconnect || true; sleep 2; $WARP connect; wait_connected ;;
    # A fresh device identity: the daemon re-enrols from mdm.xml by itself
    # and the org hands out the next addresses.
    reregister) daemon; $WARP registration delete || true; wait_for 45 registered; wait_connected ;;
    # The device with only its v4 left: the name must come from the running
    # daemon and the resolvers, whichever v4 shape the org hands out.
    no-v6) daemon; ip -6 addr flush dev CloudflareWARP; ip addr show dev CloudflareWARP ;;
    disconnect) $WARP disconnect >/dev/null 2>&1 || true ;;
    *) echo "usage: vpn connect|reconnect|reregister|no-v6|disconnect" >&2; exit 2 ;;
esac
