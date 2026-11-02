#!/usr/bin/env python3
"""Compare executables seen across monitor.py runs.

    python3 compare.py run-local runner-results/macos-26 [more runs...]

The first run is the "subject" (e.g. your machine); the rest are baselines.
Prints which executables the subject runs that no baseline ever ran, and
which executables every baseline runs that the subject doesn't.
"""

import json
import sys
from collections import Counter
from pathlib import Path


def load(d):
    data = json.loads((Path(d) / "processes.json").read_text())
    return Counter(p["exe_norm"] for p in data["processes"]), data["processes"]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    subject_dir, base_dirs = sys.argv[1], sys.argv[2:]
    subject, subject_procs = load(subject_dir)
    bases = [load(d)[0] for d in base_dirs]
    in_any_base = set().union(*bases)
    in_all_bases = set.intersection(*(set(b) for b in bases))

    print(f"# {subject_dir} vs {', '.join(base_dirs)}\n")
    print(f"- subject executables: {len(subject)}")
    for d, b in zip(base_dirs, bases):
        print(f"- {d}: {len(b)} executables")
    print()

    only_subject = sorted(set(subject) - in_any_base)
    print(f"## Only in {subject_dir} ({len(only_subject)})\n")
    users = {}
    for p in subject_procs:
        users.setdefault(p["exe_norm"], set()).add(p["user"])
    for exe in only_subject:
        print(f"- `{exe}` x{subject[exe]} ({', '.join(sorted(users[exe]))})")
    print()

    missing = sorted(in_all_bases - set(subject))
    print(f"## In every baseline but not in {subject_dir} ({len(missing)})\n")
    for exe in missing:
        print(f"- `{exe}`")
    print()

    common = sorted(set(subject) & in_any_base)
    print(f"## Common ({len(common)})\n")
    for exe in common:
        print(f"- `{exe}`")


if __name__ == "__main__":
    main()
