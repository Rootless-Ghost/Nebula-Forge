-- DriftWatch tables

CREATE TABLE IF NOT EXISTS driftwatch_reports (
    id                TEXT PRIMARY KEY,
    label             TEXT NOT NULL DEFAULT '',
    total_rules       INTEGER NOT NULL DEFAULT 0,
    never_fired       INTEGER NOT NULL DEFAULT 0,
    overfiring        INTEGER NOT NULL DEFAULT 0,
    healthy           INTEGER NOT NULL DEFAULT 0,
    coverage_pct      REAL NOT NULL DEFAULT 0,
    noise_score       REAL NOT NULL DEFAULT 0,
    time_window_hours INTEGER NOT NULL DEFAULT 168,
    event_count       INTEGER NOT NULL DEFAULT 0,
    report_json       TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_driftwatch_created ON driftwatch_reports (created_at);
