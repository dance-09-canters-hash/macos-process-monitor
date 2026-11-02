#!/usr/bin/env python3
"""Sample the macOS process table over time and summarize what's running.

Stdlib only, so it runs on a stock machine or a GitHub macOS runner.

    python3 monitor.py --duration 300 --interval 2 --out run-local

Writes into --out:
    host.txt             sw_vers / hardware / boot time
    timeline.csv         process count per sample
    processes.json       every distinct process seen (pid+start time), with first/last seen
    ps_first.txt         raw `ps` at the first sample
    ps_last.txt          raw `ps` at the last sample
    launchctl_*.txt      launchd job lists (system domain needs --sudo)
    summary.md           human-readable summary
"""

import argparse
import collections
import csv
import datetime as dt
import json
import os
import pwd
import re
import subprocess
import time
from pathlib import Path

LSTART_FMT = "%a %b %d %H:%M:%S %Y"


def sh(cmd, sudo=False):
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout + (f"\n[stderr]\n{r.stderr}" if r.returncode else "")
    except Exception as e:  # noqa: BLE001 - best-effort capture
        return f"[failed: {e}]"


def boot_time():
    out = sh(["sysctl", "-n", "kern.boottime"])
    m = re.search(r"sec = (\d+)", out)
    return int(m.group(1)) if m else None


def username(uid, cache={}):
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            cache[uid] = str(uid)
    return cache[uid]


def snapshot():
    """Return {(pid, start_epoch): proc} for every process, plus raw ps text."""
    # lstart is always 5 whitespace-separated tokens; comm (full exe path) may contain spaces.
    raw = subprocess.run(
        ["ps", "-axww", "-o", "pid=,ppid=,uid=,rss=,pcpu=,lstart=,comm="],
        capture_output=True, text=True,
    ).stdout
    args_raw = subprocess.run(
        ["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True
    ).stdout
    args = {}
    for line in args_raw.splitlines():
        parts = line.strip().split(None, 1)
        if parts:
            args[int(parts[0])] = parts[1] if len(parts) > 1 else ""

    procs = {}
    for line in raw.splitlines():
        t = line.split(None, 10)
        if len(t) < 11:
            continue
        pid, ppid, uid = int(t[0]), int(t[1]), int(t[2])
        start = int(dt.datetime.strptime(" ".join(t[5:10]), LSTART_FMT).timestamp())
        procs[(pid, start)] = {
            "pid": pid,
            "ppid": ppid,
            "user": username(uid),
            "rss_kb": int(t[3]),
            "cpu": float(t[4]),
            "start": start,
            "exe": t[10],
            "args": args.get(pid, ""),
        }
    return procs, raw


def categorize(exe):
    for prefix, cat in [
        ("/System/", "apple:/System"),
        ("/usr/libexec/", "apple:/usr/libexec"),
        ("/usr/sbin/", "apple:/usr/sbin"),
        ("/usr/bin/", "apple:/usr/bin"),
        ("/sbin/", "apple:/sbin"),
        ("/bin/", "apple:/bin"),
        ("/Library/Apple/", "apple:/Library/Apple"),
        ("/Library/", "3rdparty:/Library"),
        ("/Applications/", "3rdparty:/Applications"),
        ("/opt/", "3rdparty:/opt"),
        ("/usr/local/", "3rdparty:/usr/local"),
        ("/Users/", "user:/Users"),
        ("/private/", "other:/private"),
    ]:
        if exe.startswith(prefix):
            return cat
    return "other" if exe.startswith("/") else "kernel/unknown"


def normalize_exe(exe):
    """Make paths comparable across machines (home dirs, temp dirs, versions)."""
    exe = re.sub(r"^/Users/[^/]+", "~", exe)
    exe = re.sub(r"^/private/var/folders/[^/]+/[^/]+/", "/private/var/folders/*/*/", exe)
    return exe


def collect(args, out):
    boot = boot_time()
    start_wall = time.time()
    seen = {}
    timeline = []
    first_raw = last_raw = ""
    n = 0
    while True:
        t = time.time()
        procs, raw = snapshot()
        if n == 0:
            first_raw = raw
        last_raw = raw
        for key, p in procs.items():
            if key not in seen:
                p["first_seen"] = round(t - start_wall, 1)
                p["first_sample"] = n
                seen[key] = p
            seen[key]["last_seen"] = round(t - start_wall, 1)
            seen[key]["last_sample"] = n
            seen[key]["max_rss_kb"] = max(seen[key].get("max_rss_kb", 0), p["rss_kb"])
            seen[key]["max_cpu"] = max(seen[key].get("max_cpu", 0.0), p["cpu"])
        timeline.append({
            "sample": n,
            "elapsed_s": round(t - start_wall, 1),
            "uptime_s": round(t - boot) if boot else "",
            "count": len(procs),
        })
        print(f"[{t - start_wall:6.1f}s] sample {n}: {len(procs)} processes", flush=True)
        n += 1
        if t - start_wall + args.interval > args.duration:
            break
        time.sleep(max(0, args.interval - (time.time() - t)))

    (out / "ps_first.txt").write_text(first_raw)
    (out / "ps_last.txt").write_text(last_raw)
    with open(out / "timeline.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=timeline[0].keys())
        w.writeheader()
        w.writerows(timeline)
    for p in seen.values():
        p["exe_norm"] = normalize_exe(p["exe"])
        p["category"] = categorize(p["exe"])
        p.pop("rss_kb", None)
        p.pop("cpu", None)
    meta = {"boot": boot, "monitor_start": start_wall, "samples": n,
            "interval": args.interval, "duration": args.duration}
    (out / "processes.json").write_text(json.dumps(
        {"meta": meta, "processes": sorted(seen.values(), key=lambda p: p["start"])},
        indent=1))
    return meta, list(seen.values()), timeline


def capture_host(out, sudo):
    parts = {
        "sw_vers": sh(["sw_vers"]),
        "uname": sh(["uname", "-a"]),
        "hw": sh(["sysctl", "hw.model", "hw.machine", "hw.ncpu", "hw.memsize", "kern.boottime"]),
        "whoami": sh(["id"]),
        "sip": sh(["csrutil", "status"]),
        "console_user": sh(["stat", "-f", "%Su", "/dev/console"]),
    }
    (out / "host.txt").write_text("\n".join(f"== {k} ==\n{v}" for k, v in parts.items()))
    (out / "launchctl_user.txt").write_text(sh(["launchctl", "list"]))
    (out / "launchctl_gui_print.txt").write_text(sh(["launchctl", "print", f"gui/{os.getuid()}"]))
    if sudo:
        (out / "launchctl_system.txt").write_text(sh(["launchctl", "list"], sudo=True))
        (out / "launchctl_system_print.txt").write_text(sh(["launchctl", "print", "system"], sudo=True))
    listing = []
    for d in ["/Library/LaunchDaemons", "/Library/LaunchAgents",
              os.path.expanduser("~/Library/LaunchAgents")]:
        try:
            listing.append(f"== {d} ==\n" + "\n".join(sorted(os.listdir(d))))
        except OSError as e:
            listing.append(f"== {d} ==\n[{e}]")
    (out / "launch_plists_3rdparty.txt").write_text("\n\n".join(listing) + "\n")
    return parts


def summarize(out, meta, procs, timeline, host):
    counts = [r["count"] for r in timeline]
    boot = meta["boot"]
    mstart = meta["monitor_start"]
    last = meta["samples"] - 1
    alive_end = [p for p in procs if p["last_sample"] == last]
    transient = [p for p in procs if p["last_sample"] != last]
    new_during = [p for p in procs if p["start"] >= mstart - 1]

    L = []
    L.append("# Process monitor summary\n")
    L.append("```\n" + host["sw_vers"].strip() + "\n" + host["hw"].strip() + "\n```\n")
    if boot:
        L.append(f"- Boot time: {dt.datetime.fromtimestamp(boot).isoformat()}")
        L.append(f"- Uptime when monitoring began: **{(mstart - boot) / 60:.1f} min**")
    L.append(f"- Samples: {meta['samples']} every {meta['interval']}s over {timeline[-1]['elapsed_s']}s")
    L.append(f"- Process count: first **{counts[0]}**, last **{counts[-1]}**, "
             f"min {min(counts)}, max {max(counts)}, mean {sum(counts) / len(counts):.0f}")
    L.append(f"- Distinct processes seen (pid+start): **{len(procs)}**")
    L.append(f"- Distinct executables seen: **{len({p['exe_norm'] for p in procs})}**")
    L.append(f"- Started during monitoring: {len(new_during)}; exited during monitoring: {len(transient)}")
    L.append("- Note: polling misses processes that live shorter than the interval.\n")

    if boot:
        L.append("## When the processes alive at the end were started (relative to boot)\n")
        buckets = collections.Counter()
        edges = [(10, "<10s"), (30, "10-30s"), (60, "30-60s"), (120, "1-2m"), (300, "2-5m"),
                 (600, "5-10m"), (1800, "10-30m"), (float("inf"), ">30m")]
        for p in alive_end:
            age = p["start"] - boot
            buckets[next(lbl for lim, lbl in edges if age < lim)] += 1
        L.append("| after boot | processes |\n|---|---|")
        L += [f"| {lbl} | {buckets[lbl]} |" for _, lbl in edges]
        L.append("")

    def table(title, counter, header):
        L.append(f"## {title}\n")
        L.append(f"| {header} | count |\n|---|---|")
        L.extend(f"| `{k}` | {v} |" for k, v in counter.most_common())
        L.append("")

    table("Alive at end, by user", collections.Counter(p["user"] for p in alive_end), "user")
    table("Alive at end, by category", collections.Counter(p["category"] for p in alive_end), "category")

    # Bare names (no path, or "(name)" for exited processes) can't be attributed, so skip them.
    L.append("## Non-Apple executables seen\n")
    nonapple = collections.Counter(p["exe_norm"] for p in procs
                                   if p["category"].split(":")[0] in ("3rdparty", "user", "other"))
    L.append("| executable | instances |\n|---|---|")
    L.extend(f"| `{k}` | {v} |" for k, v in sorted(nonapple.items()))
    L.append("")

    L.append("## Transient processes (started and/or exited during monitoring)\n")
    L.append("| exe | user | started (s into run) | last seen (s) | args |\n|---|---|---|---|---|")
    for p in sorted(new_during + [p for p in transient if p not in new_during],
                    key=lambda p: p["first_seen"]):
        a = p["args"].replace("|", "\\|")[:120]
        L.append(f"| `{p['exe_norm']}` | {p['user']} | {p['first_seen']} | {p['last_seen']} | `{a}` |")
    L.append("")

    table("All executables seen (instances)",
          collections.Counter(p["exe_norm"] for p in procs), "executable")

    (out / "summary.md").write_text("\n".join(L))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--duration", type=float, default=300, help="seconds to monitor (default 300)")
    ap.add_argument("--interval", type=float, default=2, help="seconds between samples (default 2)")
    ap.add_argument("--out", default="run", help="output directory")
    ap.add_argument("--sudo", action="store_true", help="also capture system launchd domain via sudo -n")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    host = capture_host(out, args.sudo)
    meta, procs, timeline = collect(args, out)
    summarize(out, meta, procs, timeline, host)
    print(f"\nWrote {out}/summary.md")


if __name__ == "__main__":
    main()
