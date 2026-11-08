# Secrets for the account-backed clients

Everything in this directory except this file and `.gitignore` is ignored by
git. A client that needs a credential names the file in its `expect.json`
(`"secret": "nordvpn.token"`); when the file is missing the client is skipped
and the run still passes, so a clone with an empty `secrets/` runs the
self-contained clients only.

Each file is one line, the credential and nothing else (trailing whitespace is
stripped). It is mounted read-only into the client container at
`/run/secrets/<name>` for the duration of the run and read from there by the
client's `vpn` script. Nothing from it is written to `out/` or published.

| file | client | how to get it |
|---|---|---|
| `nordvpn.token` | `nordvpn` | Nord Account → NordVPN → Manual setup → "Set up NordVPN manually" → Access token → Generate new token. Any free-standing token works; it is tied to your account, so treat it like a password. |
| `tailscale.authkey` | `tailscale` | Tailscale admin console → Settings → Keys → Generate auth key. Tick **Reusable** (the rig registers a fresh node every run) and **Ephemeral** (the node is removed when the container goes away, so your tailnet does not fill with dead `octomon-rig` entries). Tags off. |

Clients that need nothing: `wireguard`, `openvpn`, `unnamed` (the rig runs the
servers), `warp` (consumer WARP registers a throwaway device; the client
passes `--accept-tos` for you, so run it only if you accept Cloudflare's WARP
terms) and `faults`.

If a credential stops working the client fails with the provider's message in
`out/<client>-0.vpn.log`; replace the file and re-run that client alone:
`./run.sh nordvpn`.
