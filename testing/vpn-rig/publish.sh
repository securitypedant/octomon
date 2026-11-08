#!/usr/bin/env bash
# testing/vpn-rig/publish.sh
#
# Folds out/report.json (the allow-listed summary run.sh writes) into the
# website's record of rig runs, website/testing/vpn-rig.json, replacing any
# earlier run for the same octomon version, newest first. Then renders the
# page. Review `git diff website/testing` before committing: that file is
# what the world sees.
set -eu
cd "$(dirname "$0")"
REPO=$(git rev-parse --show-toplevel)
SITE=$REPO/website/testing/vpn-rig.json
report=out/report.json

[ -f "$report" ] || { echo "no $report: run ./run.sh first" >&2; exit 1; }
# A report with nothing but skips says nothing worth publishing.
if ! jq -e '[.clients[] | select(.status != "skipped")] | length > 0' "$report" >/dev/null; then
    echo "every client was skipped; nothing to publish" >&2; exit 1
fi
# The allow-list, enforced here as well as in run.sh: only these keys leave.
clean=$(jq '{octomon, date, host, commit, dirty,
    clients: [.clients[] | {name, status}
        + (if .reason then {reason} else {} end)
        + (if .phases then {phases: [.phases[] | {name, pass}
            + (if .device then {device, recognised_as, medium, label_has_address, key, status, exit_code, causes, checks} else {} end)
            + (if .reason then {reason} else {} end)]} else {} end)]}' "$report")

mkdir -p "$(dirname "$SITE")"
[ -f "$SITE" ] || echo '{"runs": []}' >"$SITE"
version=$(jq -r .octomon "$report")
jq --argjson run "$clean" --arg v "$version" \
    '.runs = ([$run] + [.runs[] | select(.octomon != $v)])' "$SITE" >"$SITE.tmp"
mv "$SITE.tmp" "$SITE"
echo "recorded octomon $version in website/testing/vpn-rig.json ($(jq '.runs | length' "$SITE") runs)"

(cd "$REPO" && node tools/testing.mjs)
