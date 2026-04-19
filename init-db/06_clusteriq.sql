-- ClusterIQ tables

CREATE TABLE IF NOT EXISTS clusteriq_sessions (
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL DEFAULT '',
    original_count      INTEGER NOT NULL DEFAULT 0,
    cluster_count       INTEGER NOT NULL DEFAULT 0,
    suppressed_count    INTEGER NOT NULL DEFAULT 0,
    review_count        INTEGER NOT NULL DEFAULT 0,
    escalate_count      INTEGER NOT NULL DEFAULT 0,
    noise_reduction_pct REAL NOT NULL DEFAULT 0,
    session_json        TEXT NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clusteriq_created ON clusteriq_sessions (created_at);
