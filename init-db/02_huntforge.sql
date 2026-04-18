-- HuntForge tables

CREATE TABLE IF NOT EXISTS huntforge_playbooks (
    id             TEXT PRIMARY KEY,
    technique_id   TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic         TEXT NOT NULL,
    environment    TEXT NOT NULL DEFAULT 'windows',
    log_sources    TEXT NOT NULL DEFAULT '[]',
    playbook_json  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_huntforge_technique_id ON huntforge_playbooks (technique_id);
CREATE INDEX IF NOT EXISTS idx_huntforge_tactic       ON huntforge_playbooks (tactic);
CREATE INDEX IF NOT EXISTS idx_huntforge_created_at   ON huntforge_playbooks (created_at);
