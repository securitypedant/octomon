#!/usr/bin/env python3
"""Make dist's PowerShell installer verify what it downloads.

cargo-dist's shell installer embeds each archive's SHA-256 and refuses to
unpack a download that does not match. Its PowerShell installer does not
(checked against dist 0.32.0 and the template on main), so a Windows user
running `irm … | iex` gets no integrity check at all. This script patches the
generated installer: it embeds a table of archive name → SHA-256 and inserts a
Get-FileHash check between the download and the unpack.

The hashes come from the archives themselves (hash the files on disk), not
from dist-manifest.json, so a later step that replaces the archives — code
signing — only has to run this again.

Usage: patch-installer-checksums.py <installer.ps1> <archive.zip>...

Every anchor must match exactly once. A dist upgrade that changes the
template fails this script loudly, so a release can never silently ship an
installer that skips the check.
"""

import hashlib
import pathlib
import sys

DOWNLOAD_ANCHOR = "  Invoke-DownloadFile -client $wc -url $url -path $dir_path\n"
TABLE_ANCHOR = "function Install-Binary($install_args) {\n"

CHECK = """  Invoke-DownloadFile -client $wc -url $url -path $dir_path

  # Verify the archive against the SHA-256 published with this release.
  # (Injected by .github/scripts/patch-installer-checksums.py: dist's own
  # PowerShell installer does not verify downloads; its shell installer does.)
  $expected = $Checksums[$artifact_name]
  if ($null -eq $expected) {
    throw "ERROR: no published checksum for ${artifact_name}; refusing to install an unverified archive"
  }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $dir_path).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "ERROR: checksum mismatch for ${artifact_name}: expected $expected, got $actual. The download is corrupt or has been tampered with; nothing was installed."
  }
  Write-Verbose "  sha256 verified: $actual"
"""


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    installer = pathlib.Path(argv[1])
    archives = [pathlib.Path(a) for a in argv[2:]]
    text = installer.read_text(encoding="utf-8")

    for anchor in (DOWNLOAD_ANCHOR, TABLE_ANCHOR):
        n = text.count(anchor)
        if n != 1:
            print(f"anchor found {n} times, expected 1: {anchor!r}", file=sys.stderr)
            return 1
    if "$Checksums[" in text:
        print("installer already patched", file=sys.stderr)
        return 1

    rows = []
    for a in archives:
        digest = hashlib.sha256(a.read_bytes()).hexdigest()
        rows.append(f'  "{a.name}" = "{digest}"')
        print(f"{digest}  {a.name}")
    table = (
        "# Archive name -> SHA-256, computed from the release's archives by\n"
        "# .github/scripts/patch-installer-checksums.py.\n"
        "$Checksums = @{\n" + "\n".join(rows) + "\n}\n\n"
    )

    text = text.replace(DOWNLOAD_ANCHOR, CHECK, 1)
    text = text.replace(TABLE_ANCHOR, table + TABLE_ANCHOR, 1)
    installer.write_text(text, encoding="utf-8")
    print(f"patched {installer} with {len(rows)} checksums")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
