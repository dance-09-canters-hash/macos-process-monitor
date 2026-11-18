---
exe: /sbin/launchd
vendor: Apple
verdict: expected
---
PID 1. The init process and service manager: it starts every daemon and agent
from the launchd plists in `/System/Library/Launch*`, `/Library/Launch*` and
`~/Library/LaunchAgents`, and logs each spawn and exit that `bootlog.py` reads.
