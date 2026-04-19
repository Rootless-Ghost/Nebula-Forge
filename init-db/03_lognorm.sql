-- LogNorm tables

CREATE TABLE IF NOT EXISTS lognorm_sessions (
    session_id   TEXT PRIMARY KEY,
    source_type  TEXT NOT NULL,
    filename     TEXT,
    created_at   TEXT NOT NULL,
    total_events INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lognorm_events (
    id           BIGSERIAL PRIMARY KEY,
    event_id     TEXT NOT NULL UNIQUE,
    session_id   TEXT NOT NULL REFERENCES lognorm_sessions(session_id),
    source_type  TEXT NOT NULL,
    created_at   TEXT,
    category     TEXT,
    event_action TEXT,
    severity     INTEGER DEFAULT 0,
    host_name    TEXT,
    process_name TEXT,
    user_name    TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    ecs_json     TEXT NOT NULL,
    indexed_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lognorm_events_source   ON lognorm_events (source_type);
CREATE INDEX IF NOT EXISTS idx_lognorm_events_host     ON lognorm_events (host_name);
CREATE INDEX IF NOT EXISTS idx_lognorm_events_session  ON lognorm_events (session_id);
CREATE INDEX IF NOT EXISTS idx_lognorm_events_time     ON lognorm_events (indexed_at DESC);
