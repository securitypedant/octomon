---
name: Bug report
about: Report something that isn't working
title: ""
labels: bug
---

**Describe the bug**
A clear description of what's wrong.

**To reproduce**
Steps to reproduce the behaviour.

**Expected behaviour**
What you expected to happen.

**What octomon saw**
If the bug is about what octomon reported, run it for fifteen minutes while
the problem is happening and paste the result. It is redacted (no SSID, IPs or
MACs) and is the most useful thing you can attach:

```sh
octomon --observe 15m --doctor
```

For a display or crash bug, `octomon --check` captures a snapshot of every
panel instead.

```
paste here
```

**Environment**
- octomon version (`octomon --version`):
- macOS version:
- Terminal:

**Additional context**
Anything else — screenshots (with sensitive data redacted), logs, etc.
