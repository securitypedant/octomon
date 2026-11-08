#!/bin/sh
# rig-probe <tunnel-iface> [observe-seconds]
#
# Runs inside a client container once its tunnel is up: waits for the
# interface to carry an address, runs `octomon --check` and the unredacted
# `--doctor --json`, and prints one JSON object with both, the routing table
# and errors.log, for run.sh to assert against. Everything octomon learned is
# left in place, so the next probe in the same container sees the same files
# a second connection would.
set -u
iface=$1
observe=${2:-15}

i=0
while ! ip -4 -o addr show dev "$iface" 2>/dev/null | grep -q inet; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        jq -n --arg iface "$iface" '{error: ("no IPv4 address on " + $iface + " after 30s")}'
        exit 1
    fi
    sleep 1
done
# Let the client finish its routes; wg-quick and openvpn both add them after
# the address.
sleep 2

check_out=$(octomon --check 2>&1)
check_exit=$?
doctor=$(octomon --doctor --json --full --observe "${observe}s" 2>/tmp/doctor.err)
doctor_exit=$?
if ! printf '%s' "$doctor" | jq -e . >/dev/null 2>&1; then
    doctor=$(jq -n --arg out "$doctor" --arg err "$(cat /tmp/doctor.err)" \
        '{invalid: true, stdout: $out, stderr: $err}')
fi
errors_log=$(cat "$HOME/.local/share/octomon/errors.log" 2>/dev/null || true)

jq -n \
    --arg iface "$iface" \
    --arg addr "$(ip -4 -o addr show dev "$iface" | awk '{print $4}' | head -1)" \
    --arg routes "$(ip route show; ip rule show 2>/dev/null)" \
    --argjson check_exit "$check_exit" \
    --arg check_out "$check_out" \
    --argjson doctor_exit "$doctor_exit" \
    --argjson doctor "$doctor" \
    --arg errors_log "$errors_log" \
    '{iface: $iface, addr: $addr, routes: $routes,
      check: {exit: $check_exit, out: $check_out},
      doctor_exit: $doctor_exit, doctor: $doctor, errors_log: $errors_log}'
