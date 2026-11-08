#!/usr/bin/env bash
# testing/vpn-rig/run.sh [client…]
#
# Runs real Linux VPN clients in containers against the rig's own servers (or
# a real account, where one is mounted) and checks what octomon reports for
# each: the tunnel's name, the location label, and that the location key is
# stable across reconnects, or different where it is meant to be. Hand-run
# only; never CI. See README.md.
#
# Exit status: 0 when every client that could run passed; 1 otherwise.
# Clients whose secret is missing are skipped and do not fail the run.
#
# Output, under out/: the raw probe JSON per phase (addresses, routes, keys,
# errors.log: local only, never published), and report.json, the
# allow-listed summary that publish.sh puts on the website.
set -u
cd "$(dirname "$0")"
RIG=$PWD
REPO=$(git rev-parse --show-toplevel)
OUT=$RIG/out
OBSERVE=${OBSERVE:-15}
NET=octomon-rig

if [ $# -eq 0 ]; then
    set -- $(ls clients)
fi

mkdir -p "$OUT"
rm -f "$OUT"/*.json "$OUT"/*.log

say() { printf '%s\n' "$*"; }
hr() { printf '%s\n' "----------------------------------------------------------------"; }

# ---- base image: octomon from this checkout ---------------------------------
# The context is the repository's tracked and untracked-but-not-ignored files
# (an edit in progress is included; target/, node_modules/ and media/ are not).
hr; say "building octomon-rig-base from $REPO"
if ! git -C "$REPO" ls-files -z -co --exclude-standard -x media \
    | tar --null -T - -C "$REPO" -cf - \
    | docker build -q -t octomon-rig-base -f testing/vpn-rig/Dockerfile.base - >/dev/null; then
    say "base image build failed"; exit 1
fi
OCTOMON_VERSION=$(docker run --rm octomon-rig-base octomon --version 2>/dev/null | awk '{print $2}')
say "octomon $OCTOMON_VERSION"

# The LAN every client and server shares. compose would make it for the
# servers; a client with no servers of its own (a real account) needs it too.
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

failures=0
summary=""

# One line of the allow-listed report per client: what it is, how it ended,
# and (for a run) what each phase found. Nothing in it names an address, a
# key, a hostname or a server.
client_result() { # name status reason
    jq -n --arg name "$1" --arg status "$2" --arg reason "$3" \
        '{name: $name, status: $status} + (if $reason == "" then {} else {reason: $reason} end)' \
        >"$OUT/$1.client.json"
}

run_client() {
    local name=$1 dir=clients/$1 expect
    expect=$dir/expect.json
    hr; say "client: $name"

    # Secrets: a client that names one is skipped without the file.
    local secret
    secret=$(jq -r '.secret // empty' "$expect")
    if [ -n "$secret" ] && [ ! -f "secrets/$secret" ]; then
        say "  skipped: secrets/$secret not present"
        summary+="$name\tskipped (no secrets/$secret)\n"
        client_result "$name" skipped "no credentials mounted"
        return 0
    fi

    if ! docker build -q -t "octomon-rig-$name" "$dir" >/dev/null; then
        say "  image build failed"; failures=$((failures + 1))
        summary+="$name\tFAIL (image build)\n"
        client_result "$name" fail "client image did not build"; return 1
    fi

    # The servers this client talks to.
    local servers
    servers=$(jq -r '.servers[]?' "$expect" | tr '\n' ' ')
    if [ -n "$servers" ]; then
        # shellcheck disable=SC2086
        if ! docker compose up -d --build --quiet-pull $servers >/dev/null 2>"$OUT/$name-compose.log"; then
            say "  servers failed to start, see out/$name-compose.log"
            failures=$((failures + 1)); summary+="$name\tFAIL (servers)\n"
            client_result "$name" fail "rig servers did not start"; return 1
        fi
        sleep 3
    fi

    local cname=rig-$name
    docker rm -f "$cname" >/dev/null 2>&1
    local mounts=()
    [ -n "$secret" ] && mounts=(-v "$RIG/secrets/$secret:/run/secrets/$secret:ro")
    if ! docker run -d --name "$cname" --network "$NET" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        --sysctl net.ipv4.conf.all.src_valid_mark=1 \
        ${mounts[@]+"${mounts[@]}"} "octomon-rig-$name" >/dev/null; then
        say "  container failed to start"; failures=$((failures + 1))
        summary+="$name\tFAIL (container)\n"
        client_result "$name" fail "client container did not start"; return 1
    fi

    local tunnel_re label_re medium_re
    tunnel_re=$(jq -r '.tunnel' "$expect")
    label_re=$(jq -r '.label' "$expect")
    medium_re=$(jq -r '.medium // empty' "$expect")

    local nphases i phase cmd iface before keyrule file prev_key key ok=1 pok
    nphases=$(jq '.phases | length' "$expect")
    prev_key=""
    for ((i = 0; i < nphases; i++)); do
        phase=$(jq -r ".phases[$i].name" "$expect")
        cmd=$(jq -r ".phases[$i].cmd" "$expect")
        iface=$(jq -r ".phases[$i].iface" "$expect")
        before=$(jq -r ".phases[$i].before // empty" "$expect")
        keyrule=$(jq -r ".phases[$i].key // empty" "$expect")
        file=$OUT/$name-$i.json
        pok=1
        say "  phase $((i + 1))/$nphases: $phase"

        # shellcheck disable=SC2086
        [ -n "$before" ] && docker exec "$cname" vpn $before >/dev/null 2>&1
        # shellcheck disable=SC2086
        if ! docker exec "$cname" vpn $cmd >"$OUT/$name-$i.vpn.log" 2>&1; then
            say "    FAIL: vpn $cmd (out/$name-$i.vpn.log)"; ok=0
            jq -n --arg name "$phase" '{name: $name, pass: false, reason: "the client did not connect"}' >"$OUT/$name-$i.phase.json"
            break
        fi
        docker exec "$cname" rig-probe "$iface" "$OBSERVE" >"$file" 2>"$OUT/$name-$i.probe.log"
        if ! jq -e '.doctor.network' "$file" >/dev/null 2>&1; then
            say "    FAIL: no doctor report (out/$name-$i.json, out/$name-$i.probe.log)"; ok=0
            jq -n --arg name "$phase" '{name: $name, pass: false, reason: "octomon produced no report"}' >"$OUT/$name-$i.phase.json"
            break
        fi

        local tunnel label medium
        tunnel=$(jq -r '.doctor.network.tunnel // ""' "$file")
        label=$(jq -r '.doctor.location.label // ""' "$file")
        medium=$(jq -r '.doctor.network.medium // ""' "$file")
        key=$(jq -r '.doctor.location.key // ""' "$file")
        say "    tunnel=$tunnel"
        say "    label=$label"
        say "    medium=$medium  iface=$iface  addr=$(jq -r .addr "$file")"
        say "    key=$key"
        say "    --check exit $(jq -r .check.exit "$file")"

        local name_ok=true label_ok=true key_ok=true log_ok=true
        if ! [[ $tunnel =~ $tunnel_re ]]; then say "    FAIL: tunnel !~ /$tunnel_re/"; pok=0; name_ok=false; fi
        if ! [[ $label =~ $label_re ]]; then say "    FAIL: label !~ /$label_re/"; pok=0; label_ok=false; fi
        if [ -n "$medium_re" ] && ! [[ $medium =~ $medium_re ]]; then say "    FAIL: medium !~ /$medium_re/"; pok=0; fi
        if [ -z "$key" ]; then say "    FAIL: no location key"; pok=0; key_ok=false; fi
        case "$keyrule" in
            same) [ "$key" = "$prev_key" ] || { say "    FAIL: key changed across reconnect (was $prev_key)"; pok=0; key_ok=false; } ;;
            different) [ "$key" != "$prev_key" ] || { say "    FAIL: key did not change (expected a new location)"; pok=0; key_ok=false; } ;;
        esac
        if jq -r .errors_log "$file" | grep -Eq 'panic|supervisor'; then
            say "    FAIL: errors.log has a panic or a supervisor line"; pok=0; log_ok=false
        fi
        [ "$pok" = 1 ] || ok=0
        prev_key=$key

        # The phase's allow-listed record. "label_has_address" is the one
        # fact about the label that matters (WireGuard keys on its address,
        # OpenVPN and unnamed tunnels must not); the label itself stays local.
        jq -n --arg name "$phase" --arg device "$iface" --arg tunnel "$tunnel" --arg medium "$medium" \
            --arg keyrule "${keyrule:-first}" \
            --argjson label_has_address "$([[ $label =~ ([0-9]+\.){3}[0-9]+$ || $label =~ :[0-9a-f]*$ ]] && echo true || echo false)" \
            --argjson name_ok "$name_ok" --argjson label_ok "$label_ok" --argjson key_ok "$key_ok" --argjson log_ok "$log_ok" \
            --argjson pass "$([ "$pok" = 1 ] && echo true || echo false)" \
            '{name: $name, device: $device, recognised_as: $tunnel, medium: $medium,
              label_has_address: $label_has_address, key: $keyrule,
              checks: {name: $name_ok, label: $label_ok, key: $key_ok, clean_log: $log_ok}, pass: $pass}' \
            >"$OUT/$name-$i.phase.json"
    done

    docker exec "$cname" vpn disconnect >/dev/null 2>&1
    docker exec "$cname" sh -c 'cat $HOME/.local/share/octomon/errors.log 2>/dev/null' >"$OUT/$name-errors.log"
    docker rm -f "$cname" >/dev/null 2>&1

    if [ "$ok" = 1 ]; then
        say "  PASS"; summary+="$name\tpass\n"; client_result "$name" pass ""
    else
        say "  FAIL"; failures=$((failures + 1)); summary+="$name\tFAIL\n"; client_result "$name" fail ""
    fi
    # Fold the phases into the client's record.
    jq -s '.[0] + {phases: .[1:]}' "$OUT/$name.client.json" "$OUT/$name"-*.phase.json >"$OUT/$name.client.tmp" 2>/dev/null \
        && mv "$OUT/$name.client.tmp" "$OUT/$name.client.json"
}

for c in "$@"; do
    if [ ! -f "clients/$c/expect.json" ]; then
        say "no such client: $c (see clients/)"; failures=$((failures + 1)); continue
    fi
    run_client "$c"
done

docker compose down >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1

# ---- the report ------------------------------------------------------------
# Everything publish.sh will put on the website, and nothing else: version,
# date, where it ran, the commit octomon was built from (and whether the
# tree had uncommitted changes to it, since the base image is built from the
# working tree), and the per-client records built above.
jq -n --arg version "$OCTOMON_VERSION" --arg date "$(date -u +%Y-%m-%d)" \
    --arg host "Linux containers on Docker Desktop (macOS host)" \
    --arg commit "$(git -C "$REPO" rev-parse --short HEAD)" \
    --argjson dirty "$(git -C "$REPO" status --porcelain -- . ':!website' ':!media' | grep -q . && echo true || echo false)" \
    --slurpfile clients <(jq -s . "$OUT"/*.client.json) \
    '{octomon: $version, date: $date, host: $host, commit: $commit, dirty: $dirty, clients: $clients[0]}' \
    >"$OUT/report.json"

hr
printf "$summary" | column -t -s $'\t'
say "reports in $OUT (report.json is the publishable summary)"
[ "$failures" -eq 0 ]
