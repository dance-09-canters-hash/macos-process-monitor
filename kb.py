#!/usr/bin/env python3
"""Relational store and generated wiki for monitor.py / bootlog.py runs.

Three layers:
    data/*.csv    concrete facts, one CSV per table (schema.sql). Committed, diffable.
    notes/        hand-written prose, one Markdown file per executable or launchd
                  service, linked to the data by front matter (see notes/README.md).
    docs/wiki/    generated from both. Don't edit it by hand.

    python3 kb.py ingest run-local runner-results/macos-26 [--host NAME]
    python3 kb.py wiki
    python3 kb.py sql "select exe, count(*) from process group by exe order by 2 desc limit 10"

Every command first rebuilds kb.db (gitignored) from data/*.csv and notes/.
`ingest` adds or replaces runs, then rewrites data/*.csv; `wiki` regenerates
docs/wiki/.
"""

import argparse
import collections
import csv
import datetime as dt
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path

import bootlog
import monitor

ROOT = Path(__file__).resolve().parent
DATA, NOTES, WIKI, DB = ROOT / "data", ROOT / "notes", ROOT / "docs" / "wiki", ROOT / "kb.db"
# Load order respects foreign keys.
TABLES = ["host", "run", "executable", "process", "service", "spawn"]
ORDER = {"host": "host", "run": "run_id", "executable": "exe", "process": "run_id, pid, start_epoch",
         "service": "label", "spawn": "run_id, t_s, pid"}


# ---------------------------------------------------------------- database

def build():
    """Fresh kb.db from schema.sql + data/*.csv + notes/."""
    DB.unlink(missing_ok=True)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.executescript((ROOT / "schema.sql").read_text())
    for t in TABLES:
        path = DATA / f"{t}.csv"
        if not path.exists():
            continue
        with open(path, newline="") as f:
            r = csv.reader(f)
            cols = next(r)
            db.executemany(
                f"INSERT INTO {t} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                ([v if v != "" else None for v in row] for row in r))
    load_notes(db)
    db.commit()
    return db


def export(db):
    DATA.mkdir(exist_ok=True)
    for t in TABLES:
        cur = db.execute(f"SELECT * FROM {t} ORDER BY {ORDER[t]}")
        with open(DATA / f"{t}.csv", "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(d[0] for d in cur.description)
            w.writerows(cur)


def parse_front_matter(text):
    meta, body = {}, text
    if text.startswith("---\n"):
        head, sep, rest = text[4:].partition("\n---\n")
        if sep:
            body = rest
            for line in head.splitlines():
                k, _, v = line.partition(":")
                if v:
                    meta[k.strip()] = v.strip()
    return meta, body.strip()


def load_notes(db):
    for path in sorted(NOTES.glob("*/*.md")):
        meta, body = parse_front_matter(path.read_text())
        if not (meta.get("exe") or meta.get("service")):
            print(f"warning: {path.relative_to(ROOT)} has no exe:/service: key, skipped", file=sys.stderr)
            continue
        db.execute("INSERT INTO note VALUES (?,?,?,?,?,?,?)",
                   (str(path.relative_to(ROOT)), meta.get("exe"), meta.get("service"),
                    meta.get("title"), meta.get("vendor"), meta.get("verdict"), body))


# ---------------------------------------------------------------- ingest

def parse_host_txt(path):
    if not path.exists():
        return {}
    text = path.read_text()

    def grab(pat):
        m = re.search(pat, text, re.M)
        return m.group(1).strip() if m else None
    return {
        "os_version": grab(r"^ProductVersion:\s*(.+)$"),
        "os_build": grab(r"^BuildVersion:\s*(.+)$"),
        "model": grab(r"^hw\.model:\s*(.+)$"),
        "machine": grab(r"^hw\.machine:\s*(.+)$"),
        "ncpu": grab(r"^hw\.ncpu:\s*(\d+)"),
        "memsize": grab(r"^hw\.memsize:\s*(\d+)"),
        "sip": grab(r"System Integrity Protection status:\s*([^.\n]+)"),
    }


def scrub(s):
    """Keep usernames out of committed data."""
    return re.sub(r"/Users/[^/\s]+", "~", s or "")


def ingest(db, run_dir, host):
    d = Path(run_dir)
    data = json.loads((d / "processes.json").read_text())
    meta = data["meta"]
    h = parse_host_txt(d / "host.txt")
    start = dt.datetime.fromtimestamp(meta["monitor_start"], dt.timezone.utc)
    run_id = f"{host}_{start:%Y%m%dT%H%MZ}"

    db.execute("DELETE FROM run WHERE run_id = ?", (run_id,))  # cascades
    db.execute("""INSERT INTO host VALUES (?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET
                  model=excluded.model, machine=excluded.machine,
                  ncpu=excluded.ncpu, memsize=excluded.memsize""",
               (host, h.get("model"), h.get("machine"), h.get("ncpu"), h.get("memsize")))
    db.execute("INSERT INTO run VALUES (?,?,?,?,?,?,?,?,?,?)",
               (run_id, host, h.get("os_version"), h.get("os_build"), h.get("sip"), meta["boot"],
                meta["monitor_start"], meta["samples"], meta["interval"], meta["duration"]))

    for p in data["processes"]:
        exe = p.get("exe_norm") or monitor.normalize_exe(p["exe"])
        db.execute("INSERT OR IGNORE INTO executable VALUES (?,?)",
                   (exe, p.get("category") or monitor.categorize(p["exe"])))
        db.execute("INSERT OR REPLACE INTO process VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (run_id, p["pid"], p["start"], p["ppid"], p["user"], exe, scrub(p["args"]),
                    p["first_seen"], p["last_seen"], p.get("max_rss_kb"), p.get("max_cpu")))

    raw = next((r for r in (d / "launchd_spawns.ndjson", d / "launchd_spawns.ndjson.gz") if r.exists()), None)
    nspawn = 0
    if raw and meta["boot"]:
        events = list(bootlog.parse(raw))
        exits = {(e[1], e[2]): e[4] for e in events if e[3] == "exit"}
        for t, svc, pid, kind, reason in events:
            if kind != "spawn":
                continue
            label = bootlog.service_label(svc)
            db.execute("INSERT OR IGNORE INTO service VALUES (?,?)", (label, label.split("/", 1)[0]))
            db.execute("INSERT OR REPLACE INTO spawn VALUES (?,?,?,?,?,?)",
                       (run_id, pid, round(t - meta["boot"], 3), label, reason, exits.get((svc, pid))))
            nspawn += 1
    print(f"{run_dir} -> run {run_id}: {len(data['processes'])} processes, {nspawn} spawns")


def prune(db):
    db.execute("DELETE FROM executable WHERE exe NOT IN (SELECT exe FROM process)")
    db.execute("DELETE FROM service WHERE label NOT IN (SELECT service FROM spawn)")
    db.execute("DELETE FROM host WHERE host NOT IN (SELECT host FROM run)")


# ---------------------------------------------------------------- wiki

class Slugs:
    """Stable, unique, filesystem-safe page names."""

    def __init__(self):
        self.by_key, self.used = {}, set()

    def __call__(self, key):
        if key not in self.by_key:
            base = re.sub(r"[^A-Za-z0-9._]+", "-", key).strip("-.").lower() or "root"
            s, n = base, 2
            while s in self.used:
                s, n = f"{base}-{n}", n + 1
            self.used.add(s)
            self.by_key[key] = s
        return self.by_key[key]


def cell(v):
    return "" if v is None else str(v).replace("|", "\\|").replace("\n", " ")


def code(v):
    return f"`{cell(v)}`" if v not in (None, "") else ""


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return out + [""]


def median(xs):
    xs = sorted(x for x in xs if x is not None)
    return xs[len(xs) // 2] if xs else None


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if epoch else ""


BANNER = "<!-- Generated by kb.py from data/ and notes/. Edit those, then run `python3 kb.py wiki`. -->\n"


def render(db):
    if WIKI.exists():
        shutil.rmtree(WIKI)
    for sub in ("executables", "services", "runs", "hosts"):
        (WIKI / sub).mkdir(parents=True)
    exe_slug, svc_slug, run_slug, host_slug = Slugs(), Slugs(), Slugs(), Slugs()
    q = lambda sql, *a: db.execute(sql, a).fetchall()  # noqa: E731

    notes = {}
    for n in q("SELECT * FROM note"):
        notes[("exe", n["exe"]) if n["exe"] else ("svc", n["service"])] = n

    def link(kind, key, frm):
        sub, slug = {"exe": ("executables", exe_slug), "svc": ("services", svc_slug),
                     "run": ("runs", run_slug), "host": ("hosts", host_slug)}[kind]
        prefix = "" if frm == "root" else "../"
        text = f"`{cell(key)}`" if kind in ("exe", "svc") else cell(key)
        return f"[{text}]({prefix}{sub}/{slug(key)}.md)"

    def note_section(kind, key, slug):
        n = notes.get((kind, key))
        sub = "executables" if kind == "exe" else "services"
        field = "exe" if kind == "exe" else "service"
        if not n:
            return [f"_No note yet._ Add `notes/{sub}/{slug}.md` with front matter `{field}: {key}`.", ""]
        L = []
        facts = [f"**{k}:** {n[k]}" for k in ("vendor", "verdict") if n[k]]
        if facts:
            L += [" · ".join(facts), ""]
        L += [n["body"] or "_(empty note)_", "", f"<sub>Source: [{n['path']}](../../../{n['path']})</sub>", ""]
        return L

    runs = q("""SELECT r.*,
                  (SELECT count(*) FROM process p WHERE p.run_id = r.run_id) AS nproc,
                  (SELECT count(DISTINCT exe) FROM process p WHERE p.run_id = r.run_id) AS nexe,
                  (SELECT count(*) FROM spawn s WHERE s.run_id = r.run_id) AS nspawn
                FROM run r ORDER BY host, monitor_start""")

    # ---- executables
    exes = q("""SELECT e.exe, e.category, count(*) AS instances, count(DISTINCT p.run_id) AS nruns
                FROM executable e JOIN process p USING (exe) GROUP BY e.exe ORDER BY e.exe""")
    for e in exes:
        exe, slug = e["exe"], exe_slug(e["exe"])
        n = notes.get(("exe", exe))
        L = [BANNER, f"# `{exe}`\n", f"- Category: `{e['category']}`",
             f"- Seen in {e['nruns']} of {len(runs)} runs, {e['instances']} process instances", ""]
        L += ["## Notes\n"] + note_section("exe", exe, slug)
        L += ["## Runs\n"]
        L += table(["run", "host", "instances", "users", "first start (s after boot)", "max RSS (KB)"], [
            (link("run", r["run_id"], "page"), link("host", r["host"], "page"), r["n"], r["users"],
             r["first"], r["rss"])
            for r in q("""SELECT p.run_id, r.host, count(*) n, group_concat(DISTINCT p.user) users,
                                 min(p.start_epoch) - r.boot_epoch first, max(p.max_rss_kb) rss
                          FROM process p JOIN run r USING (run_id) WHERE p.exe = ?
                          GROUP BY p.run_id ORDER BY r.host, r.monitor_start""", exe)])
        svcs = q("SELECT service FROM service_exe WHERE exe = ? ORDER BY service", exe)
        if svcs:
            L += ["## Launched by launchd services\n"] + [f"- {link('svc', s[0], 'page')}" for s in svcs] + [""]
        for title, sql in [
            ("Parent executables", """SELECT parent_exe, count(*) FROM process_parent pp
                JOIN process p USING (run_id, pid, start_epoch) WHERE p.exe = ?
                GROUP BY parent_exe ORDER BY 2 DESC"""),
            ("Child executables", """SELECT p.exe, count(*) FROM process_parent pp
                JOIN process p USING (run_id, pid, start_epoch) WHERE pp.parent_exe = ?
                GROUP BY p.exe ORDER BY 2 DESC""")]:
            rows = q(sql, exe)
            if rows:
                L += [f"## {title}\n"] + table(["executable", "instances"],
                                                [(link("exe", r[0], "page"), r[1]) for r in rows])
        args = q("SELECT DISTINCT args FROM process WHERE exe = ? AND args != '' LIMIT 5", exe)
        if args:
            L += ["## Example command lines\n", "```"] + [a[0][:300] for a in args] + ["```", ""]
        (WIKI / "executables" / f"{slug}.md").write_text("\n".join(L))

    L = [BANNER, "# Executables\n", "[← index](../README.md)\n"]
    L += table(["executable", "category", "verdict", "runs", "instances"], [
        (link("exe", e["exe"], "page"), e["category"],
         (notes.get(("exe", e["exe"])) or {"verdict": None})["verdict"] or ("noted" if ("exe", e["exe"]) in notes else ""),
         e["nruns"], e["instances"]) for e in exes])
    (WIKI / "executables" / "README.md").write_text("\n".join(L))

    # ---- services
    svcs = q("""SELECT s.label, s.domain, count(*) AS spawns, count(DISTINCT sp.run_id) AS nruns
                FROM service s JOIN spawn sp ON sp.service = s.label GROUP BY s.label ORDER BY s.label""")
    for s in svcs:
        label, slug = s["label"], svc_slug(s["label"])
        L = [BANNER, f"# `{label}`\n", f"- Domain: `{s['domain']}`",
             f"- Spawned {s['spawns']} times across {s['nruns']} of {len(runs)} runs", ""]
        L += ["## Notes\n"] + note_section("svc", label, slug)
        bins = q("SELECT exe FROM service_exe WHERE service = ? ORDER BY exe", label)
        L += ["## Executable\n"]
        L += ([f"- {link('exe', b[0], 'page')}" for b in bins] or
              ["_Not matched: no polled process shared this spawn's pid and start time._"]) + [""]
        L += ["## Runs\n"]
        rows = []
        for r in q("""SELECT run_id, host, count(*) n, min(t_s) first, group_concat(DISTINCT reason) reasons
                      FROM spawn JOIN run USING (run_id) WHERE service = ?
                      GROUP BY run_id ORDER BY host, run_id""", label):
            ran = median(x[0] for x in q("SELECT ran_ms FROM spawn WHERE run_id = ? AND service = ?",
                                         r["run_id"], label))
            rows.append((link("run", r["run_id"], "page"), link("host", r["host"], "page"), r["n"],
                         f"{r['first']:.1f}", ran, r["reasons"]))
        L += table(["run", "host", "spawns", "first spawn (s after boot)", "median run (ms)", "reasons"], rows)
        (WIKI / "services" / f"{slug}.md").write_text("\n".join(L))

    L = [BANNER, "# launchd services\n", "[← index](../README.md)\n"]
    L += table(["service", "domain", "noted", "runs", "spawns"], [
        (link("svc", s["label"], "page"), s["domain"], "yes" if ("svc", s["label"]) in notes else "",
         s["nruns"], s["spawns"]) for s in svcs])
    (WIKI / "services" / "README.md").write_text("\n".join(L))

    # ---- runs
    for r in runs:
        rid = r["run_id"]
        L = [BANNER, f"# Run {rid}\n", "[← index](../README.md)\n",
             f"- Host: {link('host', r['host'], 'page')}",
             f"- macOS {r['os_version'] or '?'} ({r['os_build'] or '?'}), SIP {r['sip'] or '?'}",
             f"- Boot: {iso(r['boot_epoch'])}; monitoring began {iso(r['monitor_start'])}"
             + (f", {(r['monitor_start'] - r['boot_epoch']) / 60:.1f} min after boot" if r["boot_epoch"] else ""),
             f"- {r['samples']} samples every {r['interval_s']}s over {r['duration_s']}s",
             f"- {r['nproc']} process instances, {r['nexe']} executables, {r['nspawn']} launchd spawns", ""]
        L += ["## Executables by category\n"] + table(["category", "executables", "instances"], q(
            """SELECT e.category, count(DISTINCT e.exe), count(*) FROM process p JOIN executable e USING (exe)
               WHERE p.run_id = ? GROUP BY e.category ORDER BY 3 DESC""", rid))
        L += ["## Non-Apple executables\n"] + table(["executable", "category", "instances", "users"], [
            (link("exe", x[0], "page"), x[1], x[2], x[3]) for x in q(
                """SELECT e.exe, e.category, count(*), group_concat(DISTINCT p.user) FROM process p
                   JOIN executable e USING (exe) WHERE p.run_id = ?
                     AND substr(e.category, 1, instr(e.category || ':', ':') - 1) IN ('3rdparty', 'user', 'other')
                   GROUP BY e.exe ORDER BY e.exe""", rid)])
        L += ["## Only seen in this run\n"] + [f"- {link('exe', x[0], 'page')}" for x in q(
            """SELECT DISTINCT exe FROM process WHERE run_id = ?
               AND exe NOT IN (SELECT exe FROM process WHERE run_id != ?) ORDER BY exe""", rid, rid)] + [""]
        (WIKI / "runs" / f"{run_slug(rid)}.md").write_text("\n".join(L))

    # ---- hosts
    hosts = q("SELECT * FROM host ORDER BY host")
    for h in hosts:
        mem = f"{int(h['memsize']) / 2**30:.0f} GiB" if h["memsize"] else "?"
        L = [BANNER, f"# Host {h['host']}\n", "[← index](../README.md)\n",
             f"- Model: `{h['model'] or '?'}` ({h['machine'] or '?'}), {h['ncpu'] or '?'} CPUs, {mem}", "",
             "## Runs\n"]
        L += table(["run", "macOS", "processes", "executables", "spawns"], [
            (link("run", r["run_id"], "page"), r["os_version"], r["nproc"], r["nexe"], r["nspawn"])
            for r in runs if r["host"] == h["host"]])
        (WIKI / "hosts" / f"{host_slug(h['host'])}.md").write_text("\n".join(L))

    # ---- index
    nonapple = [e for e in exes if e["category"].split(":")[0] in ("3rdparty", "user", "other")]
    unnoted = [e for e in nonapple if ("exe", e["exe"]) not in notes]
    seen_exe = {e["exe"] for e in exes}
    seen_svc = {s["label"] for s in svcs}
    orphans = [n["path"] for (k, key), n in notes.items()
               if key not in (seen_exe if k == "exe" else seen_svc)]
    L = [BANNER, "# Process monitor wiki\n",
         "Readable pages over the relational data in `data/` (schema: `schema.sql`). "
         "Prose comes from `notes/`; everything else is generated by `python3 kb.py wiki`.\n",
         f"- [Executables](executables/README.md): {len(exes)} ({len(nonapple)} non-Apple)",
         f"- [launchd services](services/README.md): {len(svcs)}",
         f"- Notes: {len(notes)}", ""]
    L += ["## Hosts\n"] + table(["host", "model", "arch", "runs"], [
        (link("host", h["host"], "root"), h["model"], h["machine"],
         sum(r["host"] == h["host"] for r in runs)) for h in hosts])
    L += ["## Runs\n"] + table(["run", "host", "macOS", "boot", "processes", "executables", "spawns"], [
        (link("run", r["run_id"], "root"), r["host"], r["os_version"], iso(r["boot_epoch"]),
         r["nproc"], r["nexe"], r["nspawn"]) for r in runs])
    L += [f"## Non-Apple executables without a note ({len(unnoted)})\n"]
    L += [f"- {link('exe', e['exe'], 'root')}" for e in unnoted] + [""]
    if orphans:
        L += ["## Notes that match nothing in the data\n"] + [f"- `{p}`" for p in orphans] + [""]
    (WIKI / "README.md").write_text("\n".join(L))
    print(f"Wrote {WIKI.relative_to(ROOT)}: {len(exes)} executables, {len(svcs)} services, "
          f"{len(runs)} runs, {len(hosts)} hosts")


# ---------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("ingest", help="add/replace runs from monitor.py output dirs, rewrite data/*.csv")
    a.add_argument("dirs", nargs="+")
    a.add_argument("--host", help="host label (default: each directory's name)")
    sub.add_parser("wiki", help="regenerate docs/wiki/")
    s = sub.add_parser("sql", help="run a query against the rebuilt database")
    s.add_argument("query")
    args = ap.parse_args()

    db = build()
    if args.cmd == "ingest":
        for d in args.dirs:
            ingest(db, d, args.host or Path(d).resolve().name)
        prune(db)
        db.commit()
        export(db)
        print(f"Updated {DATA.relative_to(ROOT)}/; run `python3 kb.py wiki` to refresh the pages.")
    elif args.cmd == "wiki":
        render(db)
    else:
        cur = db.execute(args.query)
        if cur.description:
            w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
            w.writerow(d[0] for d in cur.description)
            w.writerows(cur)


if __name__ == "__main__":
    main()
