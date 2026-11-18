# macOS process monitor

- `monitor.py`: polls the process table and writes a run directory.
- `bootlog.py`: rebuilds every launchd spawn since boot from the unified log.
- `compare.py`: diffs executables between run directories.
- `kb.py`: loads runs into relational tables and generates a wiki.

## Knowledge base

| layer | where | edited by |
|---|---|---|
| Concrete facts: hosts, runs, processes, executables, launchd services, spawns | `data/*.csv`, schema in `schema.sql` | `kb.py ingest` |
| Prose: what a binary or service is, vendor, verdict | `notes/` ([format](notes/README.md)) | you |
| Readable wiki joining both | `docs/wiki/` | `kb.py wiki` (generated) |

```sh
python3 monitor.py --out run-local && python3 bootlog.py --out run-local
python3 kb.py ingest run-local runner-results/macos-26   # add/replace runs, rewrite data/*.csv
python3 kb.py wiki                                        # regenerate docs/wiki/
python3 kb.py sql "select service, exe from service_exe"  # ad-hoc SQL over everything
```

`kb.db` is rebuilt from the CSVs and notes on every command, so it's never
committed. Home-directory paths in command lines become `~`. Login usernames in
`process.user` are kept as-is, so review them before committing data from a
personal machine.
