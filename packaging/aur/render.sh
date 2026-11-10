#!/usr/bin/env bash
# Render the AUR PKGBUILD for one release from PKGBUILD.in.
#
#   render.sh <version> <out-dir>
#
# Fetches the sha256 files dist published beside the release tarballs, so the
# checksums in the PKGBUILD are the release's own and nothing is downloaded
# twice. <version> has no leading v.
set -euo pipefail

version="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
base="https://github.com/securitypedant/octomon/releases/download/v$version"

sum() {
    # dist's .sha256 files read "<hash> *<file>".
    curl -fsSL "$base/octomon-$1-unknown-linux-musl.tar.xz.sha256" | awk '{print $1}'
}
x86=$(sum x86_64)
arm=$(sum aarch64)
[[ $x86 =~ ^[0-9a-f]{64}$ && $arm =~ ^[0-9a-f]{64}$ ]] || { echo "bad checksum for $version" >&2; exit 1; }

mkdir -p "$out"
sed -e "s/@VERSION@/$version/" \
    -e "s/@SHA256_X86_64@/$x86/" \
    -e "s/@SHA256_AARCH64@/$arm/" \
    "$here/PKGBUILD.in" > "$out/PKGBUILD"
echo "$out/PKGBUILD: octomon-bin $version"
