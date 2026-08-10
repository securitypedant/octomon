# Security Policy

## Supported versions

octomon is pre-1.0; security fixes are made against the latest release and
`main`.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately using GitHub's **[Report a vulnerability](https://github.com/securitypedant/octomon/security/advisories/new)**
feature (Security → Advisories → Report a vulnerability). This opens a private
channel with the maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- affected version(s) and platform.

You can expect an initial acknowledgement within a few days. Once fixed, we'll
coordinate a release and credit you if you'd like.

## Scope notes

octomon is an unprivileged, read-only local monitor. Things worth knowing:

- It makes outbound network requests to third-party services (see the
  "Network & privacy" section of the README).
- It shells out to standard system tools (`nettop`, `traceroute`, `ps`,
  `system_profiler`) with fixed arguments; the only dynamic argument is a
  validated IP address.
- Responses from third-party endpoints are read with a hard size cap.
