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

all=0
if [ $# -eq 0 ]; then
    set -- $(ls clients)
    all=1
fi
mkdir -p "$OUT"

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

# out/ holds one run of one build. A full run starts it afresh; a run of
# some clients replaces only their records, so a client re-run after a fix
# to its phases still leaves a complete report to publish, unless the build
# changed under it, in which case everything older goes too.
build="$OCTOMON_VERSION @ $(git -C "$REPO" rev-parse --short HEAD)$(git -C "$REPO" status --porcelain -- . ':!website' ':!media' | grep -q . && echo ' (dirty)')"
if [ "$all" = 1 ] || [ "$(cat "$OUT/build" 2>/dev/null)" != "$build" ]; then
    rm -f "$OUT"/*.json "$OUT"/*.log
else
    # Phase files are <client>-<n>.*; the digit keeps "warp" off "warp-team".
    for c in "$@"; do rm -f "$OUT/$c"-[0-9]*.json "$OUT/$c"-[0-9]*.log "$OUT/$c".client.json "$OUT/$c"-compose.log "$OUT/$c"-errors.log; done
fi
printf '%s\n' "$build" >"$OUT/build"

# The LAN every client and server shares. compose would make it for the
# servers; a client with no servers of its own (a real account) needs it too.
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet 172.30.0.0/24 "$NET" >/dev/null

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

    # Secrets: a client that names one ("secret") is skipped without the
    # file. One that lists several ("secrets") runs with those present, and
    # a phase marked "needs" with one of them is skipped when it is missing.
    local secret s
    secret=$(jq -r '.secret // empty' "$expect")
    if [ -n "$secret" ] && [ ! -f "secrets/$secret" ]; then
        say "  skipped: secrets/$secret not present"
        summary+="$name\tskipped (no secrets/$secret)\n"
        client_result "$name" skipped "no credentials mounted"
        return 0
    fi
    local mounts=()
    [ -n "$secret" ] && mounts=(-v "$RIG/secrets/$secret:/run/secrets/$secret:ro")
    for s in $(jq -r '.secrets[]?' "$expect"); do
        if [ -f "secrets/$s" ]; then mounts+=(-v "$RIG/secrets/$s:/run/secrets/$s:ro")
        else say "  secrets/$s not present: its phases will be skipped"; fi
    done

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
    local ip
    # A client its server must be able to name (GRE) asks for a fixed address.
    ip=$(jq -r '.ip // empty' "$expect")
    [ -n "$ip" ] && mounts+=(--ip "$ip")
    if ! docker run -d --name "$cname" --network "$NET" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        --sysctl net.ipv4.conf.all.src_valid_mark=1 \
        ${mounts[@]+"${mounts[@]}"} "octomon-rig-$name" >/dev/null; then
        say "  container failed to start"; failures=$((failures + 1))
        summary+="$name\tFAIL (container)\n"
        client_result "$name" fail "client container did not start"; return 1
    fi

    # What every phase must satisfy, unless a phase says otherwise. A client
    # without a tunnel expectation (the fault-injection one) skips the name
    # and label checks and relies on its phases' asserts.
    local nphases i phase cmd iface before keyrule file prev_key first_key key ok=1 pok
    nphases=$(jq '.phases | length' "$expect")
    prev_key=""; first_key=""
    for ((i = 0; i < nphases; i++)); do
        phase=$(jq -r ".phases[$i].name" "$expect")
        cmd=$(jq -r ".phases[$i].cmd" "$expect")
        iface=$(jq -r ".phases[$i].iface // \"eth0\"" "$expect")
        before=$(jq -r ".phases[$i].before // empty" "$expect")
        keyrule=$(jq -r ".phases[$i].key // empty" "$expect")
        local observe
        observe=$(jq -r ".phases[$i].observe // $OBSERVE" "$expect")
        local tunnel_re label_re medium_re bypassed_re
        tunnel_re=$(jq -r ".phases[$i].tunnel // .tunnel // empty" "$expect")
        label_re=$(jq -r ".phases[$i].label // .label // empty" "$expect")
        medium_re=$(jq -r ".phases[$i].medium // .medium // empty" "$expect")
        bypassed_re=$(jq -r ".phases[$i].bypassed // .bypassed // empty" "$expect")
        file=$OUT/$name-$i.json
        pok=1
        say "  phase $((i + 1))/$nphases: $phase"
        local needs
        needs=$(jq -r ".phases[$i].needs // empty" "$expect")
        if [ -n "$needs" ] && [ ! -f "secrets/$needs" ]; then
            say "    skipped: needs secrets/$needs"
            jq -n --arg name "$phase" --arg reason "not run: no secrets/$needs" \
                '{name: $name, pass: true, skipped: true, reason: $reason}' >"$OUT/$name-$i.phase.json"
            continue
        fi

        # shellcheck disable=SC2086
        [ -n "$before" ] && docker exec "$cname" vpn $before >/dev/null 2>&1
        # shellcheck disable=SC2086
        if ! docker exec "$cname" vpn $cmd >"$OUT/$name-$i.vpn.log" 2>&1; then
            say "    FAIL: vpn $cmd (out/$name-$i.vpn.log)"; ok=0
            jq -n --arg name "$phase" '{name: $name, pass: false, reason: "the client did not connect"}' >"$OUT/$name-$i.phase.json"
            break
        fi
        docker exec "$cname" rig-probe "$iface" "$observe" >"$file" 2>"$OUT/$name-$i.probe.log"
        if ! jq -e '.doctor.network' "$file" >/dev/null 2>&1; then
            say "    FAIL: no doctor report (out/$name-$i.json, out/$name-$i.probe.log)"; ok=0
            jq -n --arg name "$phase" '{name: $name, pass: false, reason: "octomon produced no report"}' >"$OUT/$name-$i.phase.json"
            break
        fi

        local tunnel label medium bypassed status exit_code causes
        tunnel=$(jq -r '.doctor.network.tunnel // ""' "$file")
        label=$(jq -r '.doctor.location.label // ""' "$file")
        medium=$(jq -r '.doctor.network.medium // ""' "$file")
        bypassed=$(jq -r '[.doctor.network.bypassed_tunnels[]? | .vendor // .name // tostring] | join(",")' "$file")
        key=$(jq -r '.doctor.location.key // ""' "$file")
        status=$(jq -r '.doctor.status // ""' "$file")
        exit_code=$(jq -r '.doctor.exit_code // ""' "$file")
        # The causes octomon named, as its fixed slugs ("dns", "isp", …):
        # enumerations, so they can be published.
        causes=$(jq -c '[.doctor.analysis.findings[]? | .cause] | unique' "$file")
        say "    tunnel=$tunnel  bypassed=[$bypassed]"
        say "    label=$label"
        say "    medium=$medium  iface=$iface  addr=$(jq -r .addr "$file")"
        say "    key=$key"
        say "    status=$status exit=$exit_code causes=$causes  --check exit $(jq -r .check.exit "$file")"

        # checks: one named boolean per expectation this phase carries.
        local checks='{}'
        check() { # name ok
            checks=$(jq -c --arg k "$1" --argjson v "$2" '. + {($k): $v}' <<<"$checks")
            [ "$2" = true ] || pok=0
        }
        if [ -n "$tunnel_re" ]; then
            if [[ $tunnel =~ $tunnel_re ]]; then check name true; else say "    FAIL: tunnel !~ /$tunnel_re/"; check name false; fi
        fi
        if [ -n "$label_re" ]; then
            if [[ $label =~ $label_re ]]; then check label true; else say "    FAIL: label !~ /$label_re/"; check label false; fi
        fi
        if [ -n "$medium_re" ]; then
            if [[ $medium =~ $medium_re ]]; then check medium true; else say "    FAIL: medium !~ /$medium_re/"; check medium false; fi
        fi
        if [ -n "$bypassed_re" ]; then
            if [[ $bypassed =~ $bypassed_re ]]; then check bypassed true; else say "    FAIL: bypassed tunnels !~ /$bypassed_re/"; check bypassed false; fi
        fi
        local key_ok=true
        if [ -z "$key" ]; then say "    FAIL: no location key"; key_ok=false; fi
        # Key rules: same / different compare with the previous phase;
        # restored with the first one (a tunnel came down, the LAN is back).
        case "$keyrule" in
            same) [ "$key" = "$prev_key" ] || { say "    FAIL: key changed (was $prev_key)"; key_ok=false; } ;;
            different) [ "$key" != "$prev_key" ] || { say "    FAIL: key did not change (expected a new location)"; key_ok=false; } ;;
            restored) [ "$key" = "$first_key" ] || { say "    FAIL: key is not the first phase's (was $first_key)"; key_ok=false; } ;;
        esac
        check key "$key_ok"
        # Free-form asserts: a jq path on the probe's JSON and a regex its
        # (raw) value must match ("match") or must not ("absent"). The fault
        # client lives on these. Client-level asserts apply to every phase,
        # before the phase's own.
        local nasserts j apath amatch aabsent aname avalue asserts
        asserts=$(jq -c "(.asserts // []) + (.phases[$i].asserts // [])" "$expect")
        nasserts=$(jq length <<<"$asserts")
        for ((j = 0; j < nasserts; j++)); do
            aname=$(jq -r ".[$j].name" <<<"$asserts")
            apath=$(jq -r ".[$j].path" <<<"$asserts")
            amatch=$(jq -r ".[$j].match // empty" <<<"$asserts")
            aabsent=$(jq -r ".[$j].absent // empty" <<<"$asserts")
            avalue=$(jq -r "$apath" "$file" 2>/dev/null)
            if [ -n "$aabsent" ]; then
                if [[ $avalue =~ $aabsent ]]; then say "    FAIL: $aname: $apath = $(head -c 200 <<<"$avalue") =~ /$aabsent/"; check "$aname" false
                else check "$aname" true; fi
            elif [[ $avalue =~ $amatch ]]; then check "$aname" true
            else say "    FAIL: $aname: $apath = $(head -c 200 <<<"$avalue") !~ /$amatch/"; check "$aname" false; fi
        done
        if jq -r .errors_log "$file" | grep -Eq 'panic|supervisor'; then
            say "    FAIL: errors.log has a panic or a supervisor line"; check clean_log false
        else check clean_log true; fi
        [ "$pok" = 1 ] || ok=0
        prev_key=$key
        [ -n "$first_key" ] || first_key=$key

        # The phase's allow-listed record. "label_has_address" is the one
        # fact about the label that matters (WireGuard keys on its address,
        # OpenVPN and unnamed tunnels must not); the label itself stays local.
        # status, exit_code and causes are octomon's own enumerations.
        jq -n --arg name "$phase" --arg device "$iface" --arg tunnel "$tunnel" --arg medium "$medium" \
            --arg keyrule "${keyrule:-first}" --arg status "$status" --argjson exit_code "${exit_code:-null}" \
            --argjson causes "$causes" --argjson checks "$checks" \
            --argjson label_has_address "$([[ $label =~ ([0-9]+\.){3}[0-9]+$ || $label =~ :[0-9a-f]*$ ]] && echo true || echo false)" \
            --argjson pass "$([ "$pok" = 1 ] && echo true || echo false)" \
            '{name: $name, device: $device, recognised_as: $tunnel, medium: $medium,
              label_has_address: $label_has_address, key: $keyrule,
              status: $status, exit_code: $exit_code, causes: $causes,
              checks: $checks, pass: $pass}' \
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
