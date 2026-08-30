#!/usr/bin/env bash
# Preview octomon.dev locally: rebuilds website/changelog.md and the blog posts
# on save, and reloads the open tab.
#
#   ./serve-site.sh            # http://localhost:8788
#   ./serve-site.sh 9000       # a different port
#   ./serve-site.sh --open     # start, then open the changelog in a browser
#
# Only what is in website/ is served; there is no worker behind it, so /edge
# and /apt/* are not available here. For those, use `npx wrangler dev`.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

port=8788
open_browser=0
for arg in "$@"; do
  case "$arg" in
    --open) open_browser=1 ;;
    ''|*[!0-9]*) echo "usage: $0 [port] [--open]" >&2; exit 2 ;;
    *) port="$arg" ;;
  esac
done

command -v node >/dev/null || { echo "node is not installed" >&2; exit 1; }

# marked is the only dependency, and the generators cannot render without it.
if [ ! -d node_modules/marked ]; then
  echo "  installing build dependencies (npm ci)"
  npm ci
fi

if [ "$open_browser" = 1 ]; then
  # The server prints its banner and then blocks, so the open has to be armed
  # beforehand. A second is enough for node to bind the port.
  ( sleep 1
    url="http://localhost:${port}/changelog"
    if command -v open >/dev/null; then open "$url"
    elif command -v xdg-open >/dev/null; then xdg-open "$url"
    fi ) &
fi

exec node tools/serve.mjs --port "$port"
