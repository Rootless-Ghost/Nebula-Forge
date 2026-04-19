-- ============================================================
-- Nebula Forge — Tools Schema  v3
-- PostgreSQL 15+
--
-- Changes from v2 tools schema:
--
--   FIXED  (6 mechanical corrections — schema only, no app code needed)
--   LogNorm:    host_ip INET → INET[], event_id semantic fix,
--               event_source rename, log_level/raw_message made nullable stubs
--   HuntForge:  title → technique_name alias, data_sources/hunt_steps/
--               detection_logic restructured to match app output shape,
--               sigma_rule_id/version made nullable
--   ClusterIQ:  decision enum review→monitor, suppressed→suppress fix,
--               alert_ids→member_events JSONB (app stores dicts not UUIDs),
--               score accepts 0.0–1.0 float, verdict_reason rename
--   AtomicLoop: executor_type CHECK adds command_prompt,
--               stdout_excerpt/stderr_excerpt note raw_output mapping,
--               cleanup_ran default clarified, artifacts→events rename
--   VulnForge:  severity/source CHECK values lowercased + exploitdb added,
--               published_at accepts date text cast, technique_id/cwe_id
--               noted as adapter-populated
--   WifiForge:  detection_type restructured to one-row-per-network model,
--               signal_dbm←rssi rename, severity lowercase, technique_ids[]
--               for multiple techniques, mock_mode adapter note
--
--   PENDING  (code changes required first — decisions made, not yet built)
--   DriftWatch: behavioral columns now, structural diff columns stubbed nullable
--   SigmaForge: manual-save persistence pattern, dac_json column added
--
-- Load order: nebula_forge_schema_v2.sql → this file
-- ============================================================

-- ============================================================
-- SHARED LOOKUP: sigma_rules  (unchanged from v2)
-- ============================================================
CREATE TABLE sigma_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_uuid       TEXT        NOT NULL UNIQUE,
    title           TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'experimental'
                                CHECK (status IN ('stable','test','experimental','deprecated')),
    technique_id    TEXT        REFERENCES mitre_techniques(technique_id),
    tactic          TEXT,
    level           TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (level IN ('critical','high','medium','low','informational')),
    sigma_yaml      TEXT        NOT NULL,
    source_tool     TEXT        NOT NULL DEFAULT 'sigmaforge'
                                CHECK (source_tool IN ('sigmaforge','manual','imported')),
    created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    org_id          UUID        REFERENCES organizations(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sigma_org       ON sigma_rules(org_id);
CREATE INDEX idx_sigma_technique ON sigma_rules(technique_id);
CREATE INDEX idx_sigma_status    ON sigma_rules(status);
CREATE TRIGGER trg_sigma_updated BEFORE UPDATE ON sigma_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- LOGNORM  (port 5006)
--
-- FIXED: host_ip INET → INET[]  (app produces list of IPs)
-- FIXED: event_id renamed original_event_id (Windows EID, not UUID)
-- FIXED: event_source renamed source_type (matches app field name)
-- FIXED: log_level / raw_message made nullable — app doesn't produce
--        these; columns kept as stubs for future use
-- NOTE:  process_parent changed to JSONB — app stores nested dict
--        (name, pid, executable, command_line), not a flat string
-- NOTE:  run_id still required — adapter must create detection_runs
--        row first and inject run_id before inserting here
-- ============================================================
CREATE TABLE lognorm_events (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id               UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    original_event_id    TEXT,                          -- Windows EID e.g. "4688", "1"
    source_type          TEXT,                          -- "sysmon" | "wazuh" | "windows_security"
    host_name            TEXT,
    host_ip              INET[],                        -- array: app produces multiple IPs per host
    process_name         TEXT,
    process_command_line TEXT,
    process_pid          INT,
    process_parent       JSONB       DEFAULT '{}',      -- nested: name, pid, executable, command_line
    user_name            TEXT,
    log_level            TEXT,                          -- stub: app doesn't produce this yet
    raw_message          TEXT,                          -- stub: lives in ecs_event→log.original_log
    ecs_event            JSONB       NOT NULL DEFAULT '{}',
    ingested_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_lognorm_run     ON lognorm_events(run_id);
CREATE INDEX idx_lognorm_eid     ON lognorm_events(original_event_id);
CREATE INDEX idx_lognorm_host    ON lognorm_events(host_name);
CREATE INDEX idx_lognorm_proc    ON lognorm_events(process_name);
CREATE INDEX idx_lognorm_time    ON lognorm_events(ingested_at DESC);
CREATE INDEX idx_lognorm_ecs_gin ON lognorm_events USING GIN(ecs_event);

-- ============================================================
-- HUNTFORGE  (port 5007)
--
-- FIXED: title → technique_name (matches app output field)
-- FIXED: hunt_steps → playbook_json JSONB (stores full app output:
--        queries, artifacts, hypothesis, confidence — not a steps array)
-- FIXED: data_sources pulled from artifacts.log_sources in adapter
-- FIXED: detection_logic → queries JSONB (multi-backend: splunk/kql/sigma/wazuh)
-- FIXED: sigma_rule_id nullable (app generates YAML string, no UUID yet)
-- FIXED: version removed (not in app output)
-- NOTE:  run_id still requires adapter injection
-- ============================================================
CREATE TABLE huntforge_playbooks (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    technique_id    TEXT        REFERENCES mitre_techniques(technique_id),
    technique_name  TEXT,                              -- direct from app output
    tactic          TEXT,
    data_sources    TEXT[]      NOT NULL DEFAULT '{}', -- extracted from artifacts.log_sources
    queries         JSONB       NOT NULL DEFAULT '{}', -- {splunk, kql, sigma, wazuh} query strings
    playbook_json   JSONB       NOT NULL DEFAULT '{}', -- full app output blob
    sigma_rule_id   UUID        REFERENCES sigma_rules(id) ON DELETE SET NULL, -- nullable: no UUID yet
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_huntforge_run  ON huntforge_playbooks(run_id);
CREATE INDEX idx_huntforge_tech ON huntforge_playbooks(technique_id);

-- ============================================================
-- DRIFTWATCH  (port 5008)
--
-- PENDING — app code changes required before this table is usable.
-- Decision made: behavioral columns now, structural diff stubbed for v2.
--
-- behavioral_status: maps directly to app output (never_fired/overfiring/healthy)
-- hit_count, rate_per_hour, tuning_suggestions: app output fields
-- structural diff columns (baseline_hash, live_hash, structural_drift_type,
--   diff_summary, diff_detail): all nullable stubs — populated when
--   structural diffing is added to DriftWatch in a future version
-- gap_type: derivable from behavioral_status (never_fired → rule_no_fire)
--   but no_rule vs rule_not_deployed still not distinguishable until
--   structural diff is built
-- severity: FIXED — added 'informational' to CHECK (Sigma's actual value)
-- ============================================================
CREATE TABLE driftwatch_findings (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id               UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    sigma_rule_id        UUID        REFERENCES sigma_rules(id) ON DELETE SET NULL,
    rule_id_text         TEXT,                          -- rule_id from app (no UUID yet)
    rule_title           TEXT,

    -- Behavioral columns (app produces these now)
    behavioral_status    TEXT
                         CHECK (behavioral_status IN ('never_fired','overfiring','healthy')),
    hit_count            INT,
    rate_per_hour        NUMERIC(8,2),
    false_positive_est   NUMERIC(5,2),
    tuning_suggestions   JSONB       NOT NULL DEFAULT '[]', -- list of suggestion strings
    last_seen            TIMESTAMPTZ,

    -- Gap type (derivable from behavioral_status via adapter)
    gap_type             TEXT
                         CHECK (gap_type IN ('no_rule','rule_no_fire','rule_not_deployed')),

    -- Severity: FIXED — informational added to match Sigma's level field
    severity             TEXT        NOT NULL DEFAULT 'medium'
                         CHECK (severity IN ('critical','high','medium','low','info','informational')),

    resolved             BOOLEAN     NOT NULL DEFAULT false,
    resolved_at          TIMESTAMPTZ,

    -- Structural diff stubs (nullable — populated when DriftWatch v2 is built)
    baseline_hash        TEXT,                          -- stub: SHA of baseline YAML
    live_hash            TEXT,                          -- stub: SHA of current rule YAML
    structural_drift_type TEXT                          -- stub: field_rename | logic_change |
                         CHECK (structural_drift_type IS NULL OR structural_drift_type IN (
                             'field_rename','logic_change','new_rule',
                             'missing_rule','threshold_change'
                         )),
    diff_summary         TEXT,                          -- stub: human-readable diff
    diff_detail          JSONB,                         -- stub: structured field-level diff

    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_drift_run      ON driftwatch_findings(run_id);
CREATE INDEX idx_drift_rule     ON driftwatch_findings(sigma_rule_id);
CREATE INDEX idx_drift_status   ON driftwatch_findings(behavioral_status);
CREATE INDEX idx_drift_open     ON driftwatch_findings(resolved) WHERE resolved = false;

-- ============================================================
-- CLUSTERIQ  (port 5009)
--
-- FIXED: decision CHECK — review→monitor, suppressed→suppress
-- FIXED: alert_ids UUID[] → member_events JSONB (app stores full
--        alert dicts, not UUIDs; UUID array requires alerts table
--        integration first — stub that as alert_ids nullable)
-- FIXED: score — kept NUMERIC but adapter must multiply 0.0–1.0
--        similarity_score × 100, or use context_score directly
-- FIXED: decision_reason ← verdict_reason (rename only)
-- FIXED: cluster_label — adapter generates from fingerprint dict
-- NOTE:  run_id still requires adapter injection
-- ============================================================
CREATE TABLE clusteriq_clusters (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    cluster_label   TEXT        NOT NULL,              -- generated from stringified fingerprint
    member_events   JSONB       NOT NULL DEFAULT '[]', -- full alert dicts from app (members list)
    alert_ids       UUID[]      DEFAULT '{}',          -- nullable stub: populate after alerts integration
    technique_ids   TEXT[]      NOT NULL DEFAULT '{}',
    similarity_score NUMERIC(4,3),                     -- 0.000–1.000 direct from app
    context_score   NUMERIC(8,4),                      -- unscaled float direct from app
    decision        TEXT        NOT NULL DEFAULT 'monitor'
                                CHECK (decision IN ('escalate','monitor','suppress')),
    decision_reason TEXT,                              -- ← verdict_reason in app
    cluster_meta    JSONB       NOT NULL DEFAULT '{}', -- context_scores dict from app
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cluster_run      ON clusteriq_clusters(run_id);
CREATE INDEX idx_cluster_decision ON clusteriq_clusters(decision);

-- ============================================================
-- ATOMICLOOP  (port 5011)
--
-- FIXED: executor_type CHECK — added 'command_prompt'
-- FIXED: stdout_excerpt / stderr_excerpt — adapter truncates
--        raw_output / stderr to 4096 chars before insert
-- FIXED: artifacts → events JSONB (app stores captured WEL events,
--        not file paths; file artifacts stubbed separately)
-- FIXED: cleanup_ran — adapter sets true if cleanup_command ran
-- NOTE:  WinRM fields (target_host, target_user, winrm_remote)
--        exist in schema but run_test() doesn't populate them yet —
--        adapter must pull from remote_executor context if available
-- ============================================================
CREATE TABLE atomicloop_executions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    technique_id    TEXT        NOT NULL REFERENCES mitre_techniques(technique_id),
    test_number     INT,
    test_name       TEXT,
    executor_type   TEXT        NOT NULL DEFAULT 'powershell'
                                CHECK (executor_type IN (
                                    'powershell','cmd','command_prompt',
                                    'bash','manual','winrm'
                                )),
    -- WinRM fields (run_test() doesn't populate yet — adapter fills if available)
    target_host     TEXT,
    target_user     TEXT,
    winrm_remote    BOOLEAN     NOT NULL DEFAULT false,
    -- Execution result
    exit_code       INT,
    stdout_excerpt  TEXT,                              -- adapter: raw_output[:4096]
    stderr_excerpt  TEXT,                              -- adapter: stderr[:4096]
    success         BOOLEAN,                           -- adapter: exit_code == 0
    cleanup_ran     BOOLEAN     NOT NULL DEFAULT false,
    events          JSONB       NOT NULL DEFAULT '[]', -- captured WEL events from app
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms     INT
);
CREATE INDEX idx_atomic_run      ON atomicloop_executions(run_id);
CREATE INDEX idx_atomic_tech     ON atomicloop_executions(technique_id);
CREATE INDEX idx_atomic_host     ON atomicloop_executions(target_host);
CREATE INDEX idx_atomic_time     ON atomicloop_executions(executed_at DESC);

-- ============================================================
-- VULNFORGE  (port 5012)
--
-- FIXED: severity CHECK — lowercase + case-insensitive note for adapter
-- FIXED: source CHECK — added 'exploitdb', lowercased all values
-- FIXED: published_at — adapter casts "YYYY-MM-DD" text to TIMESTAMPTZ
-- FIXED: exploits JSONB — adapter builds normalized array from
--        exploit_type + rank + url + title per result
-- FIXED: lognorm_export — adapter calls export_lognorm() and stores
--        result as JSONB rather than file download
-- NOTE:  cwe_id / capec_id / technique_id — adapter must surface
--        these from attck_mapper internals; not in result dicts yet
-- NOTE:  cvss_vector — NVD only returns baseScore; column stays
--        nullable until full vector extraction is added
-- ============================================================
CREATE TABLE vulnforge_cves (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    cve_id          TEXT        NOT NULL,
    cwe_id          TEXT,                              -- adapter: surface from attck_mapper
    capec_id        TEXT,                              -- adapter: surface from attck_mapper
    technique_id    TEXT        REFERENCES mitre_techniques(technique_id), -- adapter: from attck_map
    cvss_score      NUMERIC(4,1),
    cvss_vector     TEXT,                              -- stub: NVD baseScore only for now
    severity        TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (severity IN ('critical','high','medium','low','none')),
                                -- adapter: lower(severity) before insert
    description     TEXT,
    published_at    TIMESTAMPTZ,                       -- adapter: cast date TEXT to TIMESTAMPTZ
    source          TEXT        NOT NULL DEFAULT 'nvd'
                                CHECK (source IN ('nvd','metasploit','exploitdb','manual')),
                                -- adapter: lower(source) before insert
    exploits        JSONB       NOT NULL DEFAULT '[]', -- adapter: normalize per-result fields
    lognorm_export  JSONB       NOT NULL DEFAULT '[]', -- adapter: call export_lognorm(), store result
    queried_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_vuln_run       ON vulnforge_cves(run_id);
CREATE INDEX idx_vuln_cve       ON vulnforge_cves(cve_id);
CREATE INDEX idx_vuln_severity  ON vulnforge_cves(severity);
CREATE INDEX idx_vuln_technique ON vulnforge_cves(technique_id);

-- ============================================================
-- WIFIFORGE  (port 5013)
--
-- FIXED: detection_type — restructured to one-row-per-network model.
--        App produces one dict per network with boolean flags (wps,
--        deauth, hidden) + findings list. Adapter expands into one
--        row per detected issue type per network.
-- FIXED: signal_dbm ← rssi (rename only)
-- FIXED: severity CHECK — adapter: lower(severity) before insert
-- FIXED: technique_ids TEXT[] (was single TEXT) — app returns list
-- FIXED: mock_mode — adapter reads app.config["MOCK_MODE"] and
--        injects into each row at insert time
-- FIXED: evil_twin / beacon_flood removed from CHECK — not implemented
--        in app; add back when detection logic is built
-- NOTE:  raw_frame stays as empty JSONB stub — Scapy discards frames
-- ============================================================
CREATE TABLE wififorge_findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    ssid            TEXT,
    bssid           TEXT,
    channel         INT,
    signal_dbm      INT,                               -- ← rssi in app
    detection_type  TEXT        NOT NULL
                                CHECK (detection_type IN (
                                    'deauth',
                                    'wps_enabled',
                                    'hidden_ssid',
                                    'open_network'
                                    -- evil_twin / beacon_flood: add when implemented
                                )),
    technique_ids   TEXT[]      NOT NULL DEFAULT '{}', -- app returns list of techniques
    severity        TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (severity IN ('critical','high','medium','low','info')),
                                -- adapter: lower(severity) before insert
    mock_mode       BOOLEAN     NOT NULL DEFAULT false, -- adapter: inject from app.config
    raw_frame       JSONB       NOT NULL DEFAULT '{}',  -- stub: Scapy discards frames
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()  -- adapter: first_seen or last_seen
);
CREATE INDEX idx_wifi_run   ON wififorge_findings(run_id);
CREATE INDEX idx_wifi_bssid ON wififorge_findings(bssid);
CREATE INDEX idx_wifi_type  ON wififorge_findings(detection_type);
CREATE INDEX idx_wifi_mock  ON wififorge_findings(mock_mode);

-- ============================================================
-- SIGMAFORGE  (CLI + Flask — rule_generator)
--
-- PENDING — app code changes required (manual save button not built yet)
-- Decision made: manual save — user hits "Save to Library" button
--   which POSTs to a new /api/save endpoint, inserting into both
--   sigma_rules and sigmaforge_jobs in one transaction.
--
-- Changes from v2:
-- FIXED: technique_ids TEXT[] (was single TEXT — rules can tag multiple)
-- FIXED: elastic_kql renamed elastic_dsl (app produces DSL/JSON not KQL)
-- FIXED: dac_json TEXT added (app produces conversions["dac_json"])
-- FIXED: mitre_tags TEXT[] — adapter extracts from rule YAML tags field
-- PENDING: template_name — needs to be added to API response before usable
-- PENDING: sigma_rule_id — set during save transaction
-- ============================================================
CREATE TABLE sigmaforge_jobs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    sigma_rule_id   UUID        REFERENCES sigma_rules(id) ON DELETE SET NULL, -- set on manual save
    technique_ids   TEXT[]      NOT NULL DEFAULT '{}', -- extracted from mitre_info list
    template_name   TEXT,                              -- PENDING: add to API response
    -- Backend outputs
    splunk_spl      TEXT,
    elastic_dsl     TEXT,                              -- renamed from elastic_kql (app produces DSL)
    elastic_eql     TEXT,
    sentinel_kql    TEXT,
    dac_json        TEXT,                              -- added: conversions["dac_json"]
    wazuh_xml       TEXT,                              -- stub: v2 backlog
    crowdstrike_fql TEXT,                              -- stub: v2 backlog
    qradar_aql      TEXT,                              -- stub: v2 backlog
    mitre_tags      TEXT[]      NOT NULL DEFAULT '{}', -- adapter: extract from YAML tags field
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sigmaforge_run  ON sigmaforge_jobs(run_id);
CREATE INDEX idx_sigmaforge_rule ON sigmaforge_jobs(sigma_rule_id);

-- ============================================================
-- OUTLIER STUBS  (unchanged from v2)
-- ============================================================
CREATE TABLE endpointforge_results (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    host_name   TEXT        NOT NULL,
    platform    TEXT        CHECK (platform IN ('windows','linux','macos')),
    technique_id TEXT       REFERENCES mitre_techniques(technique_id),
    severity    TEXT        CHECK (severity IN ('critical','high','medium','low','info')),
    findings    JSONB       NOT NULL DEFAULT '[]',
    wazuh_event JSONB       NOT NULL DEFAULT '{}',
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_epforge_run ON endpointforge_results(run_id);

CREATE TABLE snortforge_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    rule_text       TEXT        NOT NULL,
    protocol        TEXT,
    technique_id    TEXT        REFERENCES mitre_techniques(technique_id),
    performance_score INT,
    snort_version   TEXT        NOT NULL DEFAULT '3',
    multi_content   BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_snortforge_run ON snortforge_rules(run_id);

CREATE TABLE yaraforge_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    rule_name       TEXT        NOT NULL,
    rule_text       TEXT        NOT NULL,
    technique_id    TEXT        REFERENCES mitre_techniques(technique_id),
    target_type     TEXT,
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_yaraforge_run ON yaraforge_rules(run_id);

CREATE TABLE siren_incidents (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        REFERENCES detection_runs(id) ON DELETE SET NULL,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title           TEXT        NOT NULL,
    phase           TEXT        NOT NULL DEFAULT 'preparation'
                                CHECK (phase IN (
                                    'preparation','identification','containment',
                                    'eradication','recovery','lessons_learned'
                                )),
    severity        TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (severity IN ('critical','high','medium','low')),
    status          TEXT        NOT NULL DEFAULT 'open'
                                CHECK (status IN ('open','in_progress','resolved','closed')),
    timeline        JSONB       NOT NULL DEFAULT '[]',
    affected_hosts  TEXT[]      NOT NULL DEFAULT '{}',
    technique_ids   TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_siren_org    ON siren_incidents(org_id);
CREATE INDEX idx_siren_status ON siren_incidents(status);
CREATE TRIGGER trg_siren_updated BEFORE UPDATE ON siren_incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE endpointtriage_reports (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID        NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
    host_name       TEXT        NOT NULL,
    triage_phases   JSONB       NOT NULL DEFAULT '{}',
    ioc_hits        JSONB       NOT NULL DEFAULT '[]',
    collection_path TEXT,
    duration_sec    INT,
    completed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_triage_run  ON endpointtriage_reports(run_id);
CREATE INDEX idx_triage_host ON endpointtriage_reports(host_name);

-- ============================================================
-- CROSS-TOOL PIPELINE VIEW  (updated column names)
-- ============================================================
CREATE VIEW v_purple_loop_pipeline AS
SELECT
    mt.technique_id,
    mt.name                     AS technique_name,
    mt.tactic,
    ae.id                       AS atomic_exec_id,
    ae.target_host,
    ae.success                  AS exec_success,
    ae.executed_at,
    le.id                       AS lognorm_event_id,
    le.original_event_id        AS windows_eid,
    le.process_command_line,
    cc.id                       AS cluster_id,
    cc.decision                 AS clusteriq_decision,
    cc.context_score            AS cluster_score,
    df.id                       AS drift_finding_id,
    df.behavioral_status,
    df.gap_type,
    df.resolved                 AS gap_resolved,
    hp.id                       AS playbook_id,
    hp.technique_name           AS playbook_title
FROM mitre_techniques mt
LEFT JOIN atomicloop_executions  ae ON ae.technique_id = mt.technique_id
LEFT JOIN detection_runs         dr ON dr.id = ae.run_id
LEFT JOIN lognorm_events         le ON le.run_id = dr.id
LEFT JOIN clusteriq_clusters     cc ON ae.run_id = cc.run_id
LEFT JOIN driftwatch_findings    df ON df.run_id = dr.id AND df.resolved = false
LEFT JOIN huntforge_playbooks    hp ON hp.technique_id = mt.technique_id
ORDER BY ae.executed_at DESC NULLS LAST;

-- ============================================================
-- RLS (same pattern as v2 — all scoped through detection_runs)
-- ============================================================
ALTER TABLE sigma_rules              ENABLE ROW LEVEL SECURITY;
ALTER TABLE lognorm_events           ENABLE ROW LEVEL SECURITY;
ALTER TABLE huntforge_playbooks      ENABLE ROW LEVEL SECURITY;
ALTER TABLE driftwatch_findings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE clusteriq_clusters       ENABLE ROW LEVEL SECURITY;
ALTER TABLE atomicloop_executions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnforge_cves           ENABLE ROW LEVEL SECURITY;
ALTER TABLE wififorge_findings       ENABLE ROW LEVEL SECURITY;
ALTER TABLE sigmaforge_jobs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE siren_incidents          ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpointforge_results    ENABLE ROW LEVEL SECURITY;
ALTER TABLE snortforge_rules         ENABLE ROW LEVEL SECURITY;
ALTER TABLE yaraforge_rules          ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpointtriage_reports   ENABLE ROW LEVEL SECURITY;

CREATE POLICY rls_sigma_rules  ON sigma_rules      USING (org_id = current_org_id());
CREATE POLICY rls_siren        ON siren_incidents  USING (org_id = current_org_id());

CREATE POLICY rls_lognorm    ON lognorm_events        USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_huntforge  ON huntforge_playbooks   USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_drift      ON driftwatch_findings   USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_cluster    ON clusteriq_clusters    USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_atomic     ON atomicloop_executions USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_vuln       ON vulnforge_cves        USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_wifi       ON wififorge_findings    USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_sigmaforge ON sigmaforge_jobs       USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_epforge    ON endpointforge_results USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_snort      ON snortforge_rules      USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_yara       ON yaraforge_rules       USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
CREATE POLICY rls_triage     ON endpointtriage_reports USING (run_id IN (SELECT id FROM detection_runs WHERE org_id = current_org_id()));
