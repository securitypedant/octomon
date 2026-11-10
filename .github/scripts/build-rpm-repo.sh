#!/usr/bin/env bash
# Build the octomon rpm repository tree from a directory of .rpms.
#
#   build-rpm-repo.sh <rpms-dir> <out-dir> <gpg-key-id>
#
# One repository for every rpm distribution (Fedora, RHEL and its rebuilds,
# openSUSE): the binary is static, so there is nothing per-release to vary.
# Rebuilt from scratch each release, like the apt tree. The packages are
# signed (rpm --addsign) and so is the repository index (repomd.xml.asc),
# with the key already imported into the running gpg keyring.
set -euo pipefail

rpms="$1"
out="$2"
key="$3"

mkdir -p "$out"
cp "$rpms"/*.rpm "$out/"

# rpmsign reads the signing identity from macros, not arguments. Debian's
# rpm expects the binary as gpg2, which Ubuntu does not ship under that
# name, so name the one on PATH.
cat > "$HOME/.rpmmacros" <<EOF
%_signature gpg
%_gpg_name $key
%__gpg $(command -v gpg)
EOF
rpmsign --addsign "$out"/*.rpm
# Every package must now carry a signature from our key, or the repository
# would install nothing on a gpgcheck=1 system.
for f in "$out"/*.rpm; do
    rpm -qp --qf '%{NAME}-%{VERSION}.%{ARCH}: %{DSAHEADER:pgpsig} %{RSAHEADER:pgpsig}\n' "$f" \
        | grep -qi 'key id' || { echo "unsigned: $f" >&2; exit 1; }
done

createrepo_c --general-compress-type gz "$out"
gpg --batch --yes -u "$key" -abs -o "$out/repodata/repomd.xml.asc" "$out/repodata/repomd.xml"

# The public key beside the repo and the .repo file users download, so the
# install instructions never name a key that did not sign the index.
gpg --export -a "$key" > "$out/octomon.gpg"
cat > "$out/octomon.repo" <<'EOF'
[octomon]
name=octomon
baseurl=https://octomon.dev/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://octomon.dev/rpm/octomon.gpg
EOF
