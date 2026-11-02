#!/usr/bin/env python3
"""Reconstruct every launchd spawn since boot from the unified log.

Polling `ps` misses the first minutes before monitoring starts and anything
that lives shorter than the sample interval. launchd logs every spawn and exit,
so this fills both gaps.

    python3 bootlog.py --out run-local [--sudo]

Reads <out>/launchd_spawns.ndjson if present, otherwise collects it with
`log show --last boot` (slow on a machine that's been up a while). Boot time
comes from <out>/host.txt (written by monitor.py) or the live sysctl.
Writes <out>/bootlog.md.
"""

import argparse
import collections
import datetime as dt
import json
import re
import subprocess
from pathlib import Path

PREDICATE = ('process == "launchd" AND (eventMessage BEGINSWITH "Successfully spawned" '
             'OR eventMessage BEGINSWITH "exited ")')


def collect(path, sudo):
    # Full path: zsh has a `log` builtin that shadows /usr/bin/log.
    cmd = ["/usr/bin/log", "show", "--last", "boot", "--style", "ndjson", "--predicate", PREDICATE]
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    with open(path, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)


def boot_time(out):
    host = out / "host.txt"
    text = host.read_text() if host.exists() else subprocess.run(
        ["sysctl", "kern.boottime"], capture_output=True, text=True).stdout
    return int(re.search(r"\{ sec = (\d+)", text).group(1))


def parse(path):
    """Yield (epoch, service, pid, kind, detail) for spawn/exit events."""
    for line in open(path):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue  # log show prints a trailing summary object / blank lines
        msg = e.get("eventMessage", "")
        # subsystem looks like "system/com.apple.tccd.system [557]" or "gui/501/com.foo [123]"
        m = re.match(r"(.+?) \[(\d+)\]$", e.get("subsystem", ""))
        if not m:
            continue
        service, pid = m.group(1), int(m.group(2))
        service = re.sub(r"^(gui|user)/\d+/", r"\1/", service)  # drop uid
        t = dt.datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
        if msg.startswith("Successfully spawned "):
            yield t, service, pid, "spawn", msg.split(" because ", 1)[-1]
        elif msg.startswith("exited "):
            ran = re.search(r"ran for (\d+)ms", msg)
            yield t, service, pid, "exit", int(ran.group(1)) if ran else None


def summarize(out, boot, events):
    spawns = [e for e in events if e[3] == "spawn"]
    if not spawns:
        (out / "bootlog.md").write_text("# launchd spawns since boot\n\nNo spawn events found.\n")
        return
    exits = {(e[1], e[2]): e for e in events if e[3] == "exit"}
    spawns.sort()

    def domain(svc):
        return svc.split("/", 1)[0]

    def label(svc):
        # pid/<n>/<label>.<UUID> are per-instance XPC services owned by an app; group them.
        svc = re.sub(r"^pid/\d+/", "pid/*/", svc)
        return re.sub(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", "*", svc)

    L = ["# launchd spawns since boot\n"]
    L.append(f"- Boot time: {dt.datetime.fromtimestamp(boot).isoformat()}")
    L.append(f"- First logged spawn: +{spawns[0][0] - boot:.1f}s, last: +{spawns[-1][0] - boot:.1f}s")
    L.append(f"- Spawns: **{len(spawns)}**, distinct services: **{len({label(s[1]) for s in spawns})}**")
    short = [ms for (_, _, _, _, ms) in exits.values() if ms is not None and ms < 2000]
    L.append(f"- Exits logged: {len(exits)}; ran < 2s (too short for 2s polling): {len(short)}")
    L.append("- Note: the earliest boot entries (kernel, launchd itself) aren't launchd spawns.\n")

    L.append("## Cumulative spawns by time since boot\n")
    L.append("| by | spawns | distinct services |\n|---|---|---|")
    for lim, lbl in [(5, "5s"), (10, "10s"), (20, "20s"), (30, "30s"), (60, "1m"), (120, "2m"),
                     (300, "5m"), (600, "10m"), (1800, "30m"), (float("inf"), "end")]:
        within = [s for s in spawns if s[0] - boot < lim]
        L.append(f"| {lbl} | {len(within)} | {len({label(s[1]) for s in within})} |")
    L.append("")

    def table(title, counter, header):
        L.append(f"## {title}\n")
        L.append(f"| {header} | spawns |\n|---|---|")
        L.extend(f"| `{k}` | {v} |" for k, v in counter.most_common())
        L.append("")

    table("Spawns by domain", collections.Counter(domain(s[1]) for s in spawns), "domain")
    table("Spawns by reason", collections.Counter(s[4] for s in spawns), "reason")

    L.append("## Every service, in order of first spawn\n")
    L.append("| first spawn (s after boot) | service | spawns | median run (ms) | reason |")
    L.append("|---|---|---|---|---|")
    by_label = collections.OrderedDict()
    for s in spawns:
        by_label.setdefault(label(s[1]), []).append(s)
    for lbl, ss in by_label.items():
        runs = sorted(exits[(s[1], s[2])][4] for s in ss
                      if (s[1], s[2]) in exits and exits[(s[1], s[2])][4] is not None)
        med = runs[len(runs) // 2] if runs else ""
        L.append(f"| {ss[0][0] - boot:.1f} | `{lbl}` | {len(ss)} | {med} | {ss[0][4]} |")
    L.append("")
    (out / "bootlog.md").write_text("\n".join(L))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="run", help="output directory (same as monitor.py's)")
    ap.add_argument("--sudo", action="store_true", help="run `log show` via sudo -n")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "launchd_spawns.ndjson"
    if not raw.exists():
        collect(raw, args.sudo)
    summarize(out, boot_time(out), list(parse(raw)))
    print(f"Wrote {out}/bootlog.md")


if __name__ == "__main__":
    main()
