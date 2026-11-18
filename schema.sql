-- Relational model for monitor.py / bootlog.py output.
-- Committed data: data/<table>.csv for host, run, executable, process, service, spawn.
-- kb.py loads them into kb.db (gitignored) in this order, so FKs hold.

PRAGMA foreign_keys = ON;

-- A machine. Label chosen at ingest (default: the run directory's name).
CREATE TABLE host (
  host     TEXT PRIMARY KEY,
  model    TEXT,             -- hw.model
  machine  TEXT,             -- hw.machine (arm64 / x86_64)
  ncpu     INTEGER,
  memsize  INTEGER           -- bytes
);

-- One monitor.py invocation (plus bootlog.py, if it was run in the same dir).
CREATE TABLE run (
  run_id         TEXT PRIMARY KEY,   -- <host>_<monitor start, UTC>
  host           TEXT NOT NULL REFERENCES host(host),
  os_version     TEXT,
  os_build       TEXT,
  sip            TEXT,
  boot_epoch     INTEGER,
  monitor_start  REAL,
  samples        INTEGER,
  interval_s     REAL,
  duration_s     REAL
);

-- Distinct program, keyed by normalized path (monitor.normalize_exe).
CREATE TABLE executable (
  exe       TEXT PRIMARY KEY,
  category  TEXT NOT NULL            -- monitor.categorize, e.g. apple:/System
);

-- A process instance observed by polling.
CREATE TABLE process (
  run_id        TEXT NOT NULL REFERENCES run(run_id) ON DELETE CASCADE,
  pid           INTEGER NOT NULL,
  start_epoch   INTEGER NOT NULL,
  ppid          INTEGER,
  user          TEXT,
  exe           TEXT NOT NULL REFERENCES executable(exe),
  args          TEXT,                -- home directories replaced with ~
  first_seen_s  REAL,                -- seconds into the monitoring run
  last_seen_s   REAL,
  max_rss_kb    INTEGER,
  max_cpu       REAL,
  PRIMARY KEY (run_id, pid, start_epoch)
);

-- A launchd job, uid/pid/UUID stripped so instances group (bootlog.label).
CREATE TABLE service (
  label   TEXT PRIMARY KEY,
  domain  TEXT NOT NULL                -- system / gui / user / pid
);

-- A launchd spawn from the unified log.
CREATE TABLE spawn (
  run_id   TEXT NOT NULL REFERENCES run(run_id) ON DELETE CASCADE,
  pid      INTEGER NOT NULL,
  t_s      REAL NOT NULL,              -- seconds after boot
  service  TEXT NOT NULL REFERENCES service(label),
  reason   TEXT,
  ran_ms   INTEGER,                    -- from the matching exit event, if logged
  PRIMARY KEY (run_id, pid, t_s)
);

-- Hand-written notes, loaded from notes/ (not CSV). No FK: a note may
-- describe something no ingested run has seen yet.
CREATE TABLE note (
  path     TEXT PRIMARY KEY,
  exe      TEXT,
  service  TEXT,
  title    TEXT,
  vendor   TEXT,
  verdict  TEXT,                       -- e.g. expected / unknown / suspicious
  body     TEXT,
  CHECK ((exe IS NULL) <> (service IS NULL))
);

-- Derived relations.

-- Parent process: same run, pid = ppid, the latest one started before the child.
CREATE VIEW process_parent AS
SELECT c.run_id, c.pid, c.start_epoch, par.pid AS parent_pid,
       par.start_epoch AS parent_start, par.exe AS parent_exe
FROM process c
JOIN process par ON par.run_id = c.run_id AND par.pid = c.ppid
 AND par.start_epoch = (SELECT max(x.start_epoch) FROM process x
                        WHERE x.run_id = c.run_id AND x.pid = c.ppid
                          AND x.start_epoch <= c.start_epoch);

-- Which binary a launchd service runs: a spawn and a polled process share a pid
-- and their start times agree to within 2 s. Only spawns that polling also
-- caught are matched.
CREATE VIEW service_exe AS
SELECT DISTINCT s.service, p.exe
FROM spawn s
JOIN run r USING (run_id)
JOIN process p ON p.run_id = s.run_id AND p.pid = s.pid
 AND abs(p.start_epoch - (r.boot_epoch + s.t_s)) <= 2;
