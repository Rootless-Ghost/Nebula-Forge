-- ============================================================
-- Nebula Forge SaaS Schema  v2
-- PostgreSQL 15+
--
-- Changes from v1:
--   FIXED  detection_runs.user_id: NOT NULL → nullable (SET NULL safe)
--   FIXED  subscriptions: added deleted_at for soft-delete cycling
--   FIXED  v_active_alerts: INNER JOIN users → LEFT JOIN
--   ADDED  org_id denormalized onto detection_runs (RLS + perf)
--   ADDED  updated_at on orgs, users, alerts, detection_runs
--   ADDED  created_by on api_keys
--   ADDED  Row Level Security on all tenant tables
--   ADDED  technique_coverage, mitre_techniques, coverage_gaps tables
--   ADDED  v_coverage_dashboard view
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ORGANIZATIONS
-- ============================================================
CREATE TABLE organizations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    tier        TEXT        NOT NULL DEFAULT 'free'
                            CHECK (tier IN ('free','pro','enterprise')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL UNIQUE,
    role            TEXT        NOT NULL DEFAULT 'analyst'
                                CHECK (role IN ('owner','admin','analyst','viewer')),
    hashed_password TEXT        NOT NULL,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_org ON users(org_id);

-- ============================================================
-- SUBSCRIPTIONS
-- Soft-delete so canceling + resubscribing doesn't conflict.
-- ============================================================
CREATE TABLE subscriptions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan                TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active','past_due','canceled','trialing')),
    current_period_end  TIMESTAMPTZ NOT NULL,
    stripe_sub_id       TEXT        UNIQUE,
    deleted_at          TIMESTAMPTZ                          -- soft-delete; NULL = live record
);
-- Only one ACTIVE subscription per org at a time
CREATE UNIQUE INDEX idx_sub_org_active
    ON subscriptions(org_id)
    WHERE deleted_at IS NULL;

-- ============================================================
-- API KEYS
-- ============================================================
CREATE TABLE api_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by  UUID        REFERENCES users(id) ON DELETE SET NULL,   -- who made this key
    key_hash    TEXT        NOT NULL UNIQUE,
    label       TEXT        NOT NULL,
    scopes      TEXT[]      NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_org ON api_keys(org_id);

-- ============================================================
-- TOOLS
-- ============================================================
CREATE TABLE tools (
    id        UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    slug      TEXT    NOT NULL UNIQUE,
    name      TEXT    NOT NULL,
    version   TEXT    NOT NULL,
    category  TEXT    NOT NULL
              CHECK (category IN ('normalizer','hunter','analyzer','runner','scanner')),
    is_active BOOLEAN NOT NULL DEFAULT true
);

INSERT INTO tools (slug, name, version, category) VALUES
    ('lognorm',    'LogNorm',    '1.0.0', 'normalizer'),
    ('huntforge',  'HuntForge',  '1.0.0', 'hunter'),
    ('driftwatch', 'DriftWatch', '1.0.0', 'analyzer'),
    ('clusteriq',  'ClusterIQ',  '1.0.0', 'analyzer'),
    ('atomicloop', 'AtomicLoop', '1.0.0', 'runner'),
    ('vulnforge',  'VulnForge',  '1.0.0', 'scanner'),
    ('wififorge',  'WifiForge',  '1.0.0', 'scanner');

-- ============================================================
-- DETECTION RUNS
--   FIX 1: user_id now nullable so ON DELETE SET NULL works
--   FIX 2: org_id denormalized here for RLS + fast tenant scans
-- ============================================================
CREATE TABLE detection_runs (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      UUID        REFERENCES users(id) ON DELETE SET NULL,  -- nullable: ok
    tool_id      UUID        NOT NULL REFERENCES tools(id),
    technique_id TEXT,
    status       TEXT        NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending','running','success','failed','timeout')),
    params       JSONB       NOT NULL DEFAULT '{}',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_runs_org     ON detection_runs(org_id);
CREATE INDEX idx_runs_user    ON detection_runs(user_id);
CREATE INDEX idx_runs_tool    ON detection_runs(tool_id);
CREATE INDEX idx_runs_started ON detection_runs(started_at DESC);
CREATE INDEX idx_runs_tech    ON detection_runs(technique_id) WHERE technique_id IS NOT NULL;

-- ============================================================
-- ALERTS
-- ============================================================
CREATE TABLE alerts (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id       UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    severity     TEXT        NOT NULL DEFAULT 'medium'
                             CHECK (severity IN ('critical','high','medium','low','info')),
    title        TEXT        NOT NULL,
    mitre_tactic TEXT,
    raw_event    JSONB       NOT NULL DEFAULT '{}',
    acknowledged BOOLEAN     NOT NULL DEFAULT false,
    fired_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_run      ON alerts(run_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_fired    ON alerts(fired_at DESC);

-- ============================================================
-- RUN ARTIFACTS
-- ============================================================
CREATE TABLE run_artifacts (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id        UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    artifact_type TEXT        NOT NULL,
    storage_path  TEXT        NOT NULL,
    size_bytes    BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_artifacts_run ON run_artifacts(run_id);

-- ============================================================
-- AUDIT LOGS
-- ============================================================
CREATE TABLE audit_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        REFERENCES users(id) ON DELETE SET NULL,
    org_id        UUID        REFERENCES organizations(id) ON DELETE CASCADE,
    action        TEXT        NOT NULL,
    resource_type TEXT,
    resource_id   TEXT,
    metadata      JSONB       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org     ON audit_logs(org_id);
CREATE INDEX idx_audit_user    ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- ============================================================
-- NEW: MITRE ATT&CK TECHNIQUE REGISTRY
-- Reference table — one row per technique you care about.
-- Seed from MITRE ATT&CK or your own subset.
-- ============================================================
CREATE TABLE mitre_techniques (
    technique_id   TEXT        PRIMARY KEY,             -- "T1059.001"
    name           TEXT        NOT NULL,                -- "PowerShell"
    tactic         TEXT        NOT NULL,                -- "Execution"
    platform       TEXT[]      NOT NULL DEFAULT '{}',   -- {"Windows","Linux"}
    description    TEXT,
    is_priority    BOOLEAN     NOT NULL DEFAULT false,  -- flag your focus areas
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed your current purple-loop techniques
INSERT INTO mitre_techniques (technique_id, name, tactic, platform, is_priority) VALUES
    ('T1059.001', 'PowerShell',                        'Execution',            '{"Windows"}',          true),
    ('T1059.003', 'Windows Command Shell',             'Execution',            '{"Windows"}',          true),
    ('T1003',     'OS Credential Dumping',             'Credential Access',    '{"Windows","Linux"}',  true),
    ('T1055',     'Process Injection',                 'Defense Evasion',      '{"Windows","Linux"}',  true),
    ('T1547.001', 'Registry Run Keys / Startup Folder','Persistence',          '{"Windows"}',          true),
    ('T1021.006', 'Windows Remote Management',         'Lateral Movement',     '{"Windows"}',          true),
    ('T1190',     'Exploit Public-Facing Application', 'Initial Access',       '{"Windows","Linux"}',  false),
    ('T1078',     'Valid Accounts',                    'Defense Evasion',      '{"Windows","Linux"}',  false),
    ('T1110',     'Brute Force',                       'Credential Access',    '{"Windows","Linux"}',  false),
    ('T1046',     'Network Service Discovery',         'Discovery',            '{"Windows","Linux"}',  false);

-- ============================================================
-- NEW: TECHNIQUE COVERAGE
-- Per-org record of which techniques have been tested,
-- whether a detection rule exists, and if it fired correctly.
-- This is the output of your purple-loop pipeline.
-- ============================================================
CREATE TABLE technique_coverage (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    technique_id     TEXT        NOT NULL REFERENCES mitre_techniques(technique_id),
    tested           BOOLEAN     NOT NULL DEFAULT false,  -- AtomicLoop ran it
    detection_exists BOOLEAN     NOT NULL DEFAULT false,  -- Sigma rule in DriftWatch
    detection_fired  BOOLEAN     NOT NULL DEFAULT false,  -- Wazuh/SIEM actually alerted
    last_tested_at   TIMESTAMPTZ,
    last_run_id      UUID        REFERENCES detection_runs(id) ON DELETE SET NULL,
    notes            TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, technique_id)
);
CREATE INDEX idx_coverage_org  ON technique_coverage(org_id);
CREATE INDEX idx_coverage_tech ON technique_coverage(technique_id);

-- ============================================================
-- NEW: COVERAGE GAPS
-- Auto-populated by DriftWatch: techniques that are in scope
-- but have no detection rule, or a rule that didn't fire.
-- ============================================================
CREATE TABLE coverage_gaps (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    technique_id    TEXT        NOT NULL REFERENCES mitre_techniques(technique_id),
    gap_type        TEXT        NOT NULL
                                CHECK (gap_type IN (
                                    'no_rule',          -- no Sigma rule exists at all
                                    'rule_no_fire',     -- rule exists but didn't alert
                                    'rule_not_deployed' -- rule written but not in SIEM
                                )),
    detected_by     TEXT        NOT NULL DEFAULT 'driftwatch',
    resolved        BOOLEAN     NOT NULL DEFAULT false,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, technique_id, gap_type, resolved)
);
CREATE INDEX idx_gaps_org      ON coverage_gaps(org_id);
CREATE INDEX idx_gaps_resolved ON coverage_gaps(resolved) WHERE resolved = false;

-- ============================================================
-- TRIGGER: auto-update updated_at columns
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_orgs_updated     BEFORE UPDATE ON organizations      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_users_updated    BEFORE UPDATE ON users               FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_runs_updated     BEFORE UPDATE ON detection_runs      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_alerts_updated   BEFORE UPDATE ON alerts              FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_coverage_updated BEFORE UPDATE ON technique_coverage  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- ROW LEVEL SECURITY
-- Ensures queries scoped to one org can't bleed into another.
-- Your app passes the current org's UUID as a session variable.
-- Usage in app:  SET LOCAL app.current_org_id = '<uuid>';
-- ============================================================
ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys            ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_runs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_artifacts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE technique_coverage  ENABLE ROW LEVEL SECURITY;
ALTER TABLE coverage_gaps       ENABLE ROW LEVEL SECURITY;

-- Helper: current org from session variable
CREATE OR REPLACE FUNCTION current_org_id() RETURNS UUID LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('app.current_org_id', true), '')::uuid;
$$;

CREATE POLICY rls_users            ON users            USING (org_id = current_org_id());
CREATE POLICY rls_api_keys         ON api_keys         USING (org_id = current_org_id());
CREATE POLICY rls_subscriptions    ON subscriptions    USING (org_id = current_org_id());
CREATE POLICY rls_detection_runs   ON detection_runs   USING (org_id = current_org_id());
CREATE POLICY rls_alerts           ON alerts           USING (
    run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id())
);
CREATE POLICY rls_run_artifacts    ON run_artifacts    USING (
    run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id())
);
CREATE POLICY rls_audit_logs       ON audit_logs       USING (org_id = current_org_id());
CREATE POLICY rls_technique_cov    ON technique_coverage USING (org_id = current_org_id());
CREATE POLICY rls_coverage_gaps    ON coverage_gaps    USING (org_id = current_org_id());

-- ============================================================
-- VIEWS
-- ============================================================

-- FIX: LEFT JOIN so deleted-user runs still appear
CREATE VIEW v_active_alerts AS
SELECT
    a.id,
    a.severity,
    a.title,
    a.mitre_tactic,
    a.fired_at,
    t.slug        AS tool_slug,
    t.name        AS tool_name,
    u.email       AS triggered_by,   -- NULL if user was deleted
    r.technique_id,
    r.org_id
FROM alerts a
JOIN  detection_runs r ON r.id = a.run_id
JOIN  tools          t ON t.id = r.tool_id
LEFT  JOIN users     u ON u.id = r.user_id
WHERE a.acknowledged = false
ORDER BY a.fired_at DESC;

-- Per-org tool usage
CREATE VIEW v_org_tool_usage AS
SELECT
    r.org_id,
    o.slug        AS org_slug,
    t.slug        AS tool_slug,
    COUNT(r.id)   AS total_runs,
    MAX(r.started_at) AS last_run_at
FROM detection_runs r
JOIN organizations o ON o.id = r.org_id
JOIN tools         t ON t.id = r.tool_id
GROUP BY r.org_id, o.slug, t.slug;

-- Coverage dashboard: per-org summary across all priority techniques
CREATE VIEW v_coverage_dashboard AS
SELECT
    mt.technique_id,
    mt.name,
    mt.tactic,
    mt.is_priority,
    tc.org_id,
    tc.tested,
    tc.detection_exists,
    tc.detection_fired,
    tc.last_tested_at,
    CASE
        WHEN tc.tested AND tc.detection_fired  THEN 'covered'
        WHEN tc.tested AND tc.detection_exists THEN 'partial'
        WHEN tc.tested                         THEN 'gap'
        ELSE                                        'untested'
    END AS coverage_status,
    (
        SELECT gap_type
        FROM coverage_gaps g
        WHERE g.org_id = tc.org_id
          AND g.technique_id = mt.technique_id
          AND g.resolved = false
        LIMIT 1
    ) AS open_gap_type
FROM mitre_techniques mt
LEFT JOIN technique_coverage tc ON tc.technique_id = mt.technique_id
ORDER BY mt.is_priority DESC, mt.tactic, mt.technique_id;
