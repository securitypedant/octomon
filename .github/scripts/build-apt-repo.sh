#!/usr/bin/env bash
# Build the octomon apt repository tree from a directory of .debs.
#
#   build-apt-repo.sh <debs-dir> <out-dir> <gpg-key-id>
#
# Produces the static layout apt expects, rebuilt from scratch each release —
# the repository carries only the current version (older debs stay on the
# GitHub releases). Signed with the key already imported into the running
# gpg keyring (CI imports the APT_SIGNING_KEY secret first).
set -euo pipefail

debs="$1"
out="$2"
key="$3"
suite=stable
component=main

mkdir -p "$out/pool/$component/o/octomon"
cp "$debs"/*.deb "$out/pool/$component/o/octomon/"

cd "$out"
for arch in amd64 arm64; do
    bin="dists/$suite/$component/binary-$arch"
    mkdir -p "$bin"
    # Filename: fields come out relative to the repo root, which is what the
    # sources.list URL (…/apt) is.
    dpkg-scanpackages --arch "$arch" pool > "$bin/Packages"
    gzip -9 -kf "$bin/Packages"
done

cd "dists/$suite"
apt-ftparchive release \
    -o APT::FTPArchive::Release::Origin=octomon \
    -o APT::FTPArchive::Release::Label=octomon \
    -o APT::FTPArchive::Release::Suite=$suite \
    -o APT::FTPArchive::Release::Codename=$suite \
    -o APT::FTPArchive::Release::Components=$component \
    -o "APT::FTPArchive::Release::Architectures=amd64 arm64" \
    . > Release
# Both signature shapes: InRelease (inline, what modern apt fetches) and
# Release.gpg (detached, the fallback older apt asks for).
gpg --batch --yes -u "$key" --clearsign -o InRelease Release
gpg --batch --yes -u "$key" -abs -o Release.gpg Release
