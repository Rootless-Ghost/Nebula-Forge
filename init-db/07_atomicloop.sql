-- AtomicLoop tables

CREATE TABLE IF NOT EXISTS atomicloop_runs (
    id              TEXT PRIMARY KEY,
    technique_id    TEXT NOT NULL,
    test_number     INTEGER NOT NULL DEFAULT 1,
    test_name       TEXT NOT NULL DEFAULT '',
    executor_type   TEXT NOT NULL DEFAULT '',
    exit_code       INTEGER,
    executed_at     TEXT NOT NULL,
    duration_ms     INTEGER DEFAULT 0,
    event_count     INTEGER DEFAULT 0,
    detection_fired INTEGER DEFAULT -1,
    dry_run         INTEGER DEFAULT 0,
    run_json        TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_atomicloop_technique  ON atomicloop_runs (technique_id);
CREATE INDEX IF NOT EXISTS idx_atomicloop_executed   ON atomicloop_runs (executed_at DESC);
