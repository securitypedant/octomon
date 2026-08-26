# Winget packaging

octomon on the Windows Package Manager: `winget install octomon`, updated by
`winget upgrade octomon` (or `winget upgrade --all`).

The package is a **portable zip**: winget downloads the release zip that dist
already builds, unpacks it, and shims `octomon.exe` onto PATH as `octomon`.
No MSI, no code signing, no publisher account.

## How it flows

- The manifests live in Microsoft's registry, not here:
  `microsoft/winget-pkgs` → `manifests/s/SimonThorpe/Octomon/<version>/`.
- `.github/workflows/winget.yml` runs after each Release and has
  `wingetcreate` open the version-bump PR automatically. Bump PRs pass
  automated validation and usually merge without a human.
- `manifests/` in this directory is the **initial 0.7.3 submission**, kept
  here as the reference copy. After the bootstrap it is historical; the
  registry copy is maintained by the workflow.

## One-time bootstrap (in order)

1. Create a **classic PAT** with the `public_repo` scope
   (github.com → Settings → Developer settings → Personal access tokens),
   then store it: `gh secret set WINGET_TOKEN --repo securitypedant/octomon`.
2. Submit the initial manifests as a PR to `microsoft/winget-pkgs`: fork it,
   copy `manifests/s/SimonThorpe/Octomon/0.7.3/` in at the same path, and
   open the PR (title convention: `New package: SimonThorpe.Octomon version
   0.7.3`). First submissions get automated validation plus a human
   moderator pass — expect a few days, and watch the PR for bot feedback.
3. Once merged: `winget source update && winget install octomon` to verify.

## Notes

- `wingetcreate update` can only bump an existing package — until the
  bootstrap PR merges, the workflow's submissions will fail harmlessly.
- To validate a manifest locally (Windows):
  `winget validate --manifest packaging/winget/manifests/s/SimonThorpe/Octomon/0.7.3`.
- The SHA256s in the initial manifest are the published
  `*-pc-windows-msvc.zip.sha256` values for v0.7.3, verified against a fresh
  download.
