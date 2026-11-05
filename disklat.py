#!/usr/bin/env python3
"""Identify the boot drive and measure its small-I/O latency.

Stdlib only, so it runs on a stock machine or a GitHub macOS runner.
Hardware differs even within a model line (e.g. 256 GB Apple Silicon
machines with a single NAND chip, Intel/T2 Macs, Fusion drives), so the
drive is recorded next to the numbers.

    python3 disklat.py --out run-local [--sudo] [--size-mb 1024]

Writes into --out:
    disk_info.txt   diskutil / system_profiler output for the tested volume
    disk.json       drive identity + latency percentiles
    disk.md         human-readable summary

Tests (all 4 KiB, queue depth 1, on a scratch file on the tested volume):
    rand_read       random reads, page cache bypassed (F_NOCACHE; `purge` first with --sudo)
    write_fsync     random write + fsync()      (macOS: reaches the drive's cache only)
    write_fullsync  random write + F_FULLFSYNC  (macOS: flushed to stable storage)

GitHub runners are VMs, so their numbers describe virtual storage, not real hardware.
"""

import argparse
import json
import os
import platform
import plistlib
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - not on Windows anyway
    fcntl = None

IS_MAC = sys.platform == "darwin"
# Constants from <sys/fcntl.h>; older Pythons don't export them.
F_NOCACHE = getattr(fcntl, "F_NOCACHE", 48) if IS_MAC else None
F_FULLFSYNC = getattr(fcntl, "F_FULLFSYNC", 51) if IS_MAC else None
BLOCK = 4096


def sh(cmd, sudo=False):
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.stdout + (f"\n[stderr]\n{r.stderr}" if r.returncode else "")
    except Exception as e:  # noqa: BLE001 - best-effort capture
        return f"[failed: {e}]"


def diskutil_plist(target):
    try:
        r = subprocess.run(["diskutil", "info", "-plist", target], capture_output=True, timeout=60)
        return plistlib.loads(r.stdout) if r.returncode == 0 else {}
    except Exception:  # noqa: BLE001
        return {}


def drive_info(path):
    """Describe the physical drive behind `path`. Returns (summary dict, raw text)."""
    raw = []
    if not IS_MAC:
        raw.append("== df ==\n" + sh(["df", "-h", str(path)]))
        raw.append("== lsblk ==\n" + sh(["lsblk", "-o", "NAME,MODEL,SIZE,ROTA,TRAN,TYPE"]))
        return {"platform": platform.platform()}, "\n".join(raw)

    # diskutil wants a device or mount point, not an arbitrary directory.
    df = sh(["df", "-P", str(path)]).splitlines()
    dev = df[1].split()[0] if len(df) > 1 and df[1].startswith("/dev/") else str(path)
    vol = diskutil_plist(dev)
    # APFS volumes live in a synthesized container; follow it to the physical store.
    stores = vol.get("APFSPhysicalStores") or []
    store = stores[0].get("APFSPhysicalStore") if stores and isinstance(stores[0], dict) else None
    whole = None
    if store:
        whole = re.sub(r"s\d+$", "", store)
    elif vol.get("ParentWholeDisk"):
        whole = vol["ParentWholeDisk"]
    phys = diskutil_plist(whole) if whole else {}

    info = {
        "volume": vol.get("VolumeName"),
        "mount_point": vol.get("MountPoint"),
        "filesystem": vol.get("FilesystemName") or vol.get("FilesystemType"),
        "encrypted": vol.get("Encryption") or vol.get("FileVault"),
        "physical_disk": whole,
        "media_name": phys.get("MediaName") or vol.get("MediaName"),
        "protocol": phys.get("BusProtocol") or vol.get("BusProtocol"),
        "solid_state": phys.get("SolidState", vol.get("SolidState")),
        "internal": phys.get("Internal", vol.get("Internal")),
        "virtual": phys.get("VirtualOrPhysical") or vol.get("VirtualOrPhysical"),
        "disk_size_gb": round((phys.get("Size") or phys.get("TotalSize") or 0) / 1e9, 1) or None,
        "fusion": vol.get("Fusion"),
        "hw_model": sh(["sysctl", "-n", "hw.model"]).strip(),
    }
    info["device"] = dev
    raw.append(f"== diskutil info {dev} ({path}) ==\n" + sh(["diskutil", "info", dev]))
    if whole:
        raw.append(f"== diskutil info {whole} ==\n" + sh(["diskutil", "info", whole]))
    raw.append("== diskutil list ==\n" + sh(["diskutil", "list"]))
    raw.append("== system_profiler ==\n" + sh(
        ["system_profiler", "-detailLevel", "mini", "SPNVMeDataType", "SPSerialATADataType", "SPStorageDataType"]))
    return info, "\n".join(raw)


def nocache(fd):
    if F_NOCACHE is not None:
        fcntl.fcntl(fd, F_NOCACHE, 1)
    elif hasattr(os, "posix_fadvise"):
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)


def fullsync(fd):
    if F_FULLFSYNC is not None:
        fcntl.fcntl(fd, F_FULLFSYNC)
    else:
        os.fsync(fd)


def make_file(path, size):
    chunk = os.urandom(1 << 20)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        nocache(fd)
        for _ in range(size >> 20):
            os.write(fd, chunk)
        fullsync(fd)
    finally:
        os.close(fd)


def drop_cache(sudo):
    if IS_MAC and sudo:
        return "purge: " + (sh(["purge"], sudo=True).strip() or "ok")
    return "purge: skipped (needs macOS + --sudo)"


def timed(n, budget, op):
    """Run op() up to n times or until `budget` seconds pass; return latencies in µs."""
    lat = []
    deadline = time.perf_counter() + budget
    for _ in range(n):
        t0 = time.perf_counter_ns()
        op()
        lat.append((time.perf_counter_ns() - t0) / 1000)
        if time.perf_counter() > deadline:
            break
    return lat


def stats(lat):
    lat = sorted(lat)

    def pct(p):
        return round(lat[min(len(lat) - 1, int(p / 100 * len(lat)))], 1)

    return {
        "n": len(lat),
        "min_us": round(lat[0], 1),
        "p50_us": pct(50),
        "p95_us": pct(95),
        "p99_us": pct(99),
        "max_us": round(lat[-1], 1),
        "mean_us": round(statistics.fmean(lat), 1),
        "iops_qd1": round(1e6 / statistics.fmean(lat)),
    }


def run_tests(path, size, args):
    blocks = size // BLOCK
    rng = random.Random(1234)
    buf = os.urandom(BLOCK)
    results, notes = {}, [drop_cache(args.sudo)]

    fd = os.open(path, os.O_RDONLY)
    try:
        nocache(fd)
        for _ in range(args.warmup):
            os.pread(fd, BLOCK, rng.randrange(blocks) * BLOCK)
        results["rand_read"] = stats(timed(
            args.reads, args.budget, lambda: os.pread(fd, BLOCK, rng.randrange(blocks) * BLOCK)))
    finally:
        os.close(fd)

    fd = os.open(path, os.O_RDWR)
    try:
        nocache(fd)

        def w_fsync():
            os.pwrite(fd, buf, rng.randrange(blocks) * BLOCK)
            os.fsync(fd)

        def w_full():
            os.pwrite(fd, buf, rng.randrange(blocks) * BLOCK)
            fullsync(fd)

        results["write_fsync"] = stats(timed(args.writes, args.budget, w_fsync))
        results["write_fullsync"] = stats(timed(args.writes, args.budget, w_full))
        if F_FULLFSYNC is None:
            notes.append("write_fullsync: F_FULLFSYNC unavailable, used fsync()")
    finally:
        os.close(fd)
    return results, notes


def summarize(out, info, results, notes, args, size):
    L = ["# Disk latency\n"]
    L.append("| drive | |\n|---|---|")
    L.extend(f"| {k} | `{v}` |" for k, v in info.items() if v not in (None, ""))
    L.append("")
    L.append(f"4 KiB, QD1, {size >> 20} MiB scratch file on `{args.path}`. Latency in µs.\n")
    L.append("| test | n | min | p50 | p95 | p99 | max | IOPS (QD1) |\n|---|---|---|---|---|---|---|---|")
    for name, s in results.items():
        L.append(f"| {name} | {s['n']} | {s['min_us']} | **{s['p50_us']}** | {s['p95_us']} | "
                 f"{s['p99_us']} | {s['max_us']} | {s['iops_qd1']} |")
    L.append("")
    L.extend(f"- {n}" for n in notes)
    if (info.get("virtual") == "Virtual" or "virtual" in str(info.get("media_name", "")).lower()
            or str(info.get("hw_model", "")).startswith("VirtualMac")):
        L.append("- Virtual disk: numbers reflect the hypervisor's storage, not physical hardware.")
    L.append("")
    (out / "disk.md").write_text("\n".join(L))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="run", help="output directory")
    ap.add_argument("--path", default=tempfile.gettempdir(), help="directory on the volume to test")
    ap.add_argument("--size-mb", type=int, default=1024, help="scratch file size (default 1024)")
    ap.add_argument("--reads", type=int, default=5000, help="random reads (default 5000)")
    ap.add_argument("--writes", type=int, default=1000, help="writes per sync mode (default 1000)")
    ap.add_argument("--warmup", type=int, default=50, help="untimed reads first (default 50)")
    ap.add_argument("--budget", type=float, default=60, help="max seconds per test (default 60)")
    ap.add_argument("--sudo", action="store_true", help="run `purge` via sudo -n before reading")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    size = max(64, args.size_mb) << 20

    info, raw = drive_info(args.path)
    (out / "disk_info.txt").write_text(raw)

    scratch = Path(args.path) / f"disklat-{os.getpid()}.bin"
    try:
        t0 = time.time()
        make_file(scratch, size)
        print(f"wrote {size >> 20} MiB scratch file in {time.time() - t0:.1f}s", flush=True)
        results, notes = run_tests(scratch, size, args)
    finally:
        scratch.unlink(missing_ok=True)

    for name, s in results.items():
        print(f"{name:15} p50 {s['p50_us']:>9} µs  p99 {s['p99_us']:>9} µs  n={s['n']}")
    (out / "disk.json").write_text(json.dumps(
        {"drive": info, "block_bytes": BLOCK, "file_mib": size >> 20, "results": results, "notes": notes},
        indent=1, default=str))
    summarize(out, info, results, notes, args, size)
    print(f"Wrote {out}/disk.md")


if __name__ == "__main__":
    main()
