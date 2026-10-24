-- Rule sources (api/docs/architecture/content-sources.md): the platform is
-- the only fetcher of rules, templates and wordlists. A source names where
-- content comes from (a git repository today); a sync resolves the ref to a
-- commit, builds a canonical, linted, signed content pack and records it as
-- an immutable snapshot. A new snapshot is a candidate until it is promoted;
-- each source keeps a current and a previous snapshot.
--
-- Two owner scopes share one table:
--   tenant   - tenant_id set; managed by that organization only.
--   platform - tenant_id NULL; managed by platform administrators and offered
--              to organizations (availability: default_on, opt_in, hidden).
--              Organizations read a projection of it (no URL, credential, CA,
--              schedule or error text) and never change it. official marks
--              the curated sources whose rule ids keep no namespace.
--
-- Replaces template_sources: lazy sync at scan trigger and the per-file
-- scanner_templates rows a sync wrote are gone (rows already written stay as
-- uploaded templates). git sources over https are
-- carried over (their credential must be entered again: credentials now live
-- in the source, encrypted, write-only); s3, http and ssh sources are dropped.

CREATE TABLE content_sources (
    id                     uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    scope                  varchar(16) NOT NULL CHECK (scope IN ('platform', 'tenant')),
    tenant_id              uuid REFERENCES tenants(id) ON DELETE CASCADE,
    slug                   varchar(41) NOT NULL CHECK (slug ~ '^@?[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$'),
    rule_namespace         varchar(81) NOT NULL,
    name                   varchar(255) NOT NULL CHECK (length(btrim(name)) > 0),
    description            text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    kind                   varchar(40) NOT NULL CHECK (kind IN ('semgrep-rules', 'nuclei-templates', 'wordlist', 'secret-rules', 'trivy-policies')),
    origin                 varchar(20) NOT NULL CHECK (origin IN ('git', 'https-archive', 'upload', 'catalog')),
    url                    varchar(2048),
    ref                    varchar(255),
    path                   varchar(512) NOT NULL DEFAULT '',
    archive_sha256         varchar(71) CHECK (archive_sha256 IS NULL OR archive_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    auth_username          varchar(255),
    credential_encrypted   text,
    credential_hint        varchar(8),
    credential_updated_at  timestamptz,
    ca_pem                 text CHECK (ca_pem IS NULL OR length(ca_pem) <= 65536),
    license_spdx           varchar(100),
    license_service_use    boolean NOT NULL DEFAULT true,
    promotion_policy       varchar(16) NOT NULL DEFAULT 'auto' CHECK (promotion_policy IN ('auto', 'review')),
    sync_interval_minutes  integer NOT NULL DEFAULT 60 CHECK (sync_interval_minutes = 0 OR sync_interval_minutes BETWEEN 5 AND 10080),
    next_sync_at           timestamptz,
    sync_requested_at      timestamptz,
    sync_lease_until       timestamptz,
    webhook_secret_hash    varchar(64) CHECK (webhook_secret_hash IS NULL OR webhook_secret_hash ~ '^[0-9a-f]{64}$'),
    webhook_secret_set_at  timestamptz,
    storage_mode           varchar(16) NOT NULL DEFAULT 'mirror' CHECK (storage_mode IN ('mirror', 'proxy', 'tenant_hosted')),
    availability           varchar(16) CHECK (availability IN ('default_on', 'opt_in', 'hidden')),
    official               boolean NOT NULL DEFAULT false,
    enabled                boolean NOT NULL DEFAULT true,
    current_snapshot_id    uuid,
    previous_snapshot_id   uuid,
    last_sync_at           timestamptz,
    last_sync_status       varchar(16) NOT NULL DEFAULT 'pending' CHECK (last_sync_status IN ('pending', 'running', 'success', 'failed')),
    last_sync_error        varchar(2000),
    last_sync_commit       varchar(64),
    last_sync_report       jsonb,
    consecutive_failures   integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    config_changed_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    config_changed_at      timestamptz,
    -- Everyone who changed what the source fetches since its last synced
    -- snapshot: copied to that snapshot, whose promotion they may not approve.
    config_authors         uuid[] NOT NULL DEFAULT '{}',
    created_by             uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_content_sources_scope CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    CONSTRAINT chk_content_sources_availability CHECK ((scope = 'platform') = (availability IS NOT NULL)),
    CONSTRAINT chk_content_sources_official CHECK (NOT official OR scope = 'platform'),
    CONSTRAINT chk_content_sources_slug_scope CHECK (slug NOT LIKE '@%' OR scope = 'platform'),
    CONSTRAINT chk_content_sources_git CHECK (origin <> 'git' OR (url IS NOT NULL AND url ~ '^https://' AND ref IS NOT NULL)),
    CONSTRAINT chk_content_sources_archive CHECK (origin <> 'https-archive' OR (url IS NOT NULL AND url ~ '^https://' AND archive_sha256 IS NOT NULL)),
    CONSTRAINT chk_content_sources_credential CHECK ((credential_encrypted IS NULL) = (credential_updated_at IS NULL)),
    CONSTRAINT chk_content_sources_report_size CHECK (last_sync_report IS NULL OR pg_column_size(last_sync_report) <= 200000),
    CONSTRAINT uq_content_sources_id_scope UNIQUE (id, scope),
    CONSTRAINT uq_content_sources_tenant_id UNIQUE (tenant_id, id)
);

COMMENT ON TABLE content_sources IS
    'Rule sources: where rules, templates and wordlists come from. The platform is the only fetcher. scope=platform rows (tenant_id NULL) are offered to every organization and changed only by platform administrators.';
COMMENT ON COLUMN content_sources.credential_encrypted IS
    'Write-only fetch credential (username and token), encrypted with APP_ENCRYPTION_KEY and bound to the source id and host. Never returned by any API.';
COMMENT ON COLUMN content_sources.rule_namespace IS
    'Prefix of the rule ids of this source, set by the server at create and never changed: the slug for an organization source, @slug for a platform source, empty for an official one. Finding fingerprints hash the full rule id, so it is permanent.';
COMMENT ON COLUMN content_sources.webhook_secret_hash IS
    'SHA-256 of the webhook secret. A webhook call only queues a sync.';
COMMENT ON COLUMN content_sources.storage_mode IS
    'mirror: the platform fetches and keeps every retained snapshot; proxy: the platform fetches and caches; tenant_hosted: the bytes stay in the tenant network and the platform keeps only the signed pin record. Only mirror is accepted today.';
COMMENT ON COLUMN content_sources.config_changed_by IS
    'Who last changed what the source fetches; under review policy that member may not promote its candidates (four-eyes).';

CREATE UNIQUE INDEX uq_content_sources_tenant_slug ON content_sources (tenant_id, slug) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX uq_content_sources_platform_slug ON content_sources (slug) WHERE tenant_id IS NULL;
CREATE INDEX idx_content_sources_due ON content_sources (next_sync_at)
    WHERE enabled AND sync_interval_minutes > 0;
CREATE INDEX idx_content_sources_requested ON content_sources (sync_requested_at)
    WHERE sync_requested_at IS NOT NULL;

CREATE TRIGGER update_content_sources_updated_at BEFORE UPDATE ON content_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- rule_namespace is permanent: finding fingerprints hash the full rule id.
CREATE OR REPLACE FUNCTION content_sources_keep_rule_namespace() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.rule_namespace IS DISTINCT FROM OLD.rule_namespace THEN
        RAISE EXCEPTION 'content_sources.rule_namespace cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_content_sources_keep_rule_namespace BEFORE UPDATE OF rule_namespace ON content_sources
    FOR EACH ROW EXECUTE FUNCTION content_sources_keep_rule_namespace();

CREATE TABLE content_source_snapshots (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    source_id         uuid NOT NULL,
    scope             varchar(16) NOT NULL CHECK (scope IN ('platform', 'tenant')),
    tenant_id         uuid REFERENCES tenants(id) ON DELETE CASCADE,
    upstream_revision varchar(128) NOT NULL,
    ref               varchar(255),
    digest            varchar(71) NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    content_pack_id   uuid,
    platform_pack_id  uuid REFERENCES platform_content_packs(id) ON DELETE RESTRICT,
    size_bytes        bigint NOT NULL CHECK (size_bytes > 0),
    file_count        integer NOT NULL CHECK (file_count > 0),
    file_index        jsonb NOT NULL DEFAULT '[]'::jsonb,
    rules             jsonb NOT NULL DEFAULT '[]'::jsonb,
    rule_count        integer NOT NULL DEFAULT 0 CHECK (rule_count >= 0),
    tier              varchar(2) NOT NULL CHECK (tier IN ('T0', 'T1', 'T2')),
    lint              jsonb NOT NULL DEFAULT '{}'::jsonb,
    license_spdx      varchar(100),
    service_use       boolean NOT NULL DEFAULT true,
    redistribution    boolean,
    signature         jsonb NOT NULL,
    diff              jsonb NOT NULL DEFAULT '{}'::jsonb,
    checks            jsonb NOT NULL DEFAULT '{}'::jsonb,
    review_required   boolean NOT NULL DEFAULT false,
    state             varchar(16) NOT NULL DEFAULT 'candidate' CHECK (state IN ('candidate', 'promoted', 'superseded', 'rejected')),
    synced_by         uuid REFERENCES users(id) ON DELETE SET NULL,
    -- Members who changed the configuration this snapshot was synced from.
    config_authors    uuid[] NOT NULL DEFAULT '{}',
    promoted_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    promoted_at       timestamptz,
    rejected_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    rejected_at       timestamptz,
    reject_reason     varchar(500),
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_content_source_snapshots_source FOREIGN KEY (source_id, scope)
        REFERENCES content_sources (id, scope) ON DELETE CASCADE,
    CONSTRAINT fk_content_source_snapshots_tenant_source FOREIGN KEY (tenant_id, source_id)
        REFERENCES content_sources (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_content_source_snapshots_pack FOREIGN KEY (tenant_id, content_pack_id)
        REFERENCES content_packs (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_content_source_snapshots_scope CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    -- The pack holding the bytes is optional: a tenant-hosted source keeps
    -- only the signed pin record (commit, digest, file index, rule ids).
    CONSTRAINT chk_content_source_snapshots_pack CHECK (
        (scope = 'tenant' AND platform_pack_id IS NULL)
        OR (scope = 'platform' AND content_pack_id IS NULL)),
    CONSTRAINT chk_content_source_snapshots_sizes CHECK (
        pg_column_size(file_index) <= 4000000 AND pg_column_size(rules) <= 4000000
        AND pg_column_size(lint) <= 200000 AND pg_column_size(diff) <= 1000000),
    CONSTRAINT uq_content_source_snapshots_digest UNIQUE (source_id, digest)
);

COMMENT ON TABLE content_source_snapshots IS
    'Immutable snapshots of a rule source: commit, digest, file index, rule ids, lint and DSSE signature, over a content pack (tenant key) or a platform content pack (platform key).';

CREATE INDEX idx_content_source_snapshots_source ON content_source_snapshots (source_id, created_at DESC);
CREATE INDEX idx_content_source_snapshots_tenant ON content_source_snapshots (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_content_source_snapshots_pack ON content_source_snapshots (content_pack_id) WHERE content_pack_id IS NOT NULL;

ALTER TABLE content_sources
    ADD CONSTRAINT fk_content_sources_current FOREIGN KEY (current_snapshot_id)
        REFERENCES content_source_snapshots (id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_content_sources_previous FOREIGN KEY (previous_snapshot_id)
        REFERENCES content_source_snapshots (id) ON DELETE SET NULL;

-- Row-level security policies in shadow mode, like the other tenant tables.
-- Platform rows are readable by every organization; only an organization's
-- own rows are writable.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['content_sources', 'content_source_snapshots'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_platform_read', t);
    END LOOP;
END;
$$;
-- Platform rows are readable unless hidden (a hidden source is not offered:
-- its address and credential columns stay out of an organization's reach).
CREATE POLICY content_sources_platform_read ON content_sources FOR SELECT
    USING (tenant_id IS NULL AND availability IS DISTINCT FROM 'hidden');
CREATE POLICY content_source_snapshots_platform_read ON content_source_snapshots FOR SELECT
    USING (tenant_id IS NULL AND EXISTS (
        SELECT 1 FROM content_sources c WHERE c.id = source_id AND c.availability IS DISTINCT FROM 'hidden'));

-- Carry over git sources over https for the kinds the platform lints.
INSERT INTO content_sources (id, scope, tenant_id, slug, rule_namespace, name, description, kind, origin, url, ref, path,
                             enabled, next_sync_at, created_by, created_at, updated_at)
SELECT ts.id, 'tenant', ts.tenant_id,
       s.slug, s.slug,
       ts.name, left(COALESCE(ts.description, ''), 2000),
       CASE ts.template_type WHEN 'nuclei' THEN 'nuclei-templates' ELSE 'semgrep-rules' END,
       'git', btrim(ts.git_config->>'url'), btrim(ts.git_config->>'branch'),
       COALESCE(btrim(ts.git_config->>'path'), ''),
       ts.enabled, now(), ts.created_by, ts.created_at, now()
FROM template_sources ts
CROSS JOIN LATERAL (SELECT btrim(left(COALESCE(NULLIF(btrim(regexp_replace(lower(ts.name), '[^a-z0-9]+', '-', 'g'), '-'), ''), 'source'), 31), '-')
                           || '-' || right(replace(ts.id::text, '-', ''), 8) AS slug) s
WHERE ts.source_type = 'git'
  AND ts.template_type IN ('nuclei', 'semgrep')
  AND btrim(ts.git_config->>'url') ~ '^https://'
  AND NULLIF(btrim(ts.git_config->>'branch'), '') IS NOT NULL;

-- Templates a sync wrote stay in the library as uploaded templates (scans
-- that name them keep working). Nothing writes the sync columns any more;
-- they go when uploaded templates become a rule source origin.
ALTER TABLE scanner_templates DROP CONSTRAINT IF EXISTS scanner_templates_source_id_fkey;
DROP INDEX IF EXISTS idx_scanner_templates_source;
UPDATE scanner_templates
   SET source_id = NULL, sync_source = 'manual', source_path = NULL, source_commit = NULL
 WHERE source_id IS NOT NULL OR sync_source <> 'manual';

DROP TABLE template_sources;

-- The template_sources module is now Rule Sources (configs/modules/template_sources.yaml).
-- BEGIN module-registry
-- Generated by cmd/gen-modules from configs/modules.yaml. Do not edit by hand.
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)
VALUES
    ('dashboard', 'dashboard', 'Dashboard', 'Main dashboard with security overview and statistics', 'LayoutDashboard', 'core', 1, TRUE, true, 'released', NULL),
    ('assets', 'assets', 'Assets', 'The asset inventory, asset groups and every asset type', 'Server', 'core', 2, TRUE, true, 'released', NULL),
    ('findings', 'findings', 'Findings', 'Findings, approvals and exceptions, with SLA deadlines and priority classes', 'AlertTriangle', 'core', 3, TRUE, true, 'released', NULL),
    ('scans', 'scans', 'Scans', 'Scans, Scanning settings (Sensors, Profiles, Tools, Capabilities, Templates, Sources, Secret Store)', 'Search', 'core', 4, TRUE, true, 'released', NULL),
    ('attack_surface', 'attack-surface', 'Attack Surface', 'External attack surface overview — what an adversary sees before touching the network', 'Target', 'scoping', 5, TRUE, false, 'released', NULL),
    ('scope_config', 'scope-config', 'Scope Config', 'CTEM scope — which assets are in scope for prioritisation and reporting', 'Sliders', 'scoping', 6, TRUE, false, 'released', NULL),
    ('business_services', 'business-services', 'Business Services', 'Map business services to the underlying assets that power them', 'Building', 'scoping', 7, TRUE, false, 'released', NULL),
    ('ctem_cycles', 'ctem-cycles', 'CTEM Cycles', 'Gartner CTEM lifecycle — scoping, discovery, prioritisation, validation, mobilisation', 'RotateCcw', 'scoping', 8, TRUE, false, 'released', NULL),
    ('attacker_profiles', 'attacker-profiles', 'Attacker Profiles', 'Threat actor profiles used to drive attack simulation + prioritisation scoring', 'Swords', 'scoping', 9, TRUE, false, 'released', NULL),
    ('credentials', 'credentials', 'Credentials', 'Leaked credentials monitoring and detection', 'Key', 'discovery', 10, TRUE, false, 'released', NULL),
    ('relationships', 'relationships', 'Relationships', 'Asset-to-asset relationships for attack-path modelling', 'Link', 'scoping', 10, TRUE, false, 'released', NULL),
    ('scanner_templates', 'scanner-templates', 'Scanner Templates', 'Catalogue of Nuclei / Betterleaks / Semgrep templates', 'FileCode', 'settings', 10, TRUE, false, 'released', NULL),
    ('business_units', 'business-units', 'Business Units', 'Organisational units that group assets for ownership, criticality and reporting', 'Building2', 'scoping', 11, TRUE, false, 'released', NULL),
    ('components', 'components', 'Components', 'Software Components (SBOM), Ecosystems, Licenses, and vulnerability tracking', 'Package', 'discovery', 11, TRUE, false, 'released', NULL),
    ('template_sources', 'template-sources', 'Rule Sources', 'Git repositories the platform syncs rules and templates from, with snapshots and promotion', 'Database', 'settings', 11, TRUE, false, 'released', NULL),
    ('branches', 'branches', 'Branches', 'Code branches', 'GitBranch', 'discovery', 12, TRUE, false, 'released', NULL),
    ('crown_jewels', 'crown-jewels', 'Crown Jewels', 'Business-critical assets flagged for heightened prioritisation and monitoring', 'Crown', 'scoping', 12, TRUE, false, 'released', NULL),
    ('scan_workflows', 'scan-workflows', 'Scan Workflows', 'Scan workflows: the steps a scan runs, chained by what each step finds', 'GitBranch', 'settings', 12, TRUE, false, 'released', NULL),
    ('threat_model', 'threat-model', 'Threat Model', 'Continuous threat modelling derived from the asset graph and findings', 'Crosshair', 'scoping', 13, TRUE, false, 'released', NULL),
    ('threat_intel', 'threat_intel', 'Threat Intel', 'Threat actors and the threat intelligence workspace', 'Radar', 'prioritization', 20, TRUE, false, 'released', NULL),
    ('exposures', 'exposures', 'Exposures', 'Exposure management and non-CVE security issues', 'ShieldAlert', 'prioritization', 21, TRUE, false, 'released', NULL),
    ('ai_triage', 'ai_triage', 'AI Triage', 'AI-powered vulnerability triage (Bulk, Auto, Workflow, BYOK, Agent modes)', 'Brain', 'prioritization', 22, TRUE, false, 'released', NULL),
    ('ai_triage.bulk', 'ai_triage_bulk', 'Bulk Triage', 'Bulk triage operations', 'Layers', 'prioritization', 1, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.auto', 'ai_triage_auto', 'Auto Triage', 'Auto-triage on finding creation', 'Zap', 'prioritization', 2, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.workflow', 'ai_triage_workflow', 'Workflow Triage', 'Workflow triggers and actions', 'GitPullRequest', 'prioritization', 3, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.byok', 'ai_triage_byok', 'BYOK Mode', 'Bring Your Own Key mode', 'Key', 'prioritization', 4, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.agent', 'ai_triage_agent', 'Agent Mode', 'Self-hosted Agent mode', 'Cpu', 'prioritization', 5, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.custom_prompts', 'ai_triage_custom_prompts', 'Custom Prompts', 'Custom prompt templates', 'FileText', 'prioritization', 6, TRUE, false, 'released', 'ai_triage'),
    ('sla', 'sla', 'SLA Management', 'SLA policies for remediation time tracking', 'Clock', 'prioritization', 23, TRUE, true, 'released', NULL),
    ('priority_rules', 'priority-rules', 'Priority Rules', 'Declarative priority classification rules (P0..P3)', 'Sliders', 'prioritization', 24, TRUE, false, 'released', NULL),
    ('risk_analysis', 'risk-analysis', 'Risk Analysis', 'Aggregate risk dashboards across assets + findings', 'BarChart', 'prioritization', 25, TRUE, false, 'released', NULL),
    ('business_impact', 'business-impact', 'Business Impact', 'Business impact scoring weighted by business-services mapping', 'Building', 'prioritization', 26, TRUE, false, 'released', NULL),
    ('risk_scoring', 'risk-scoring', 'Risk Scoring', 'Risk scoring config — CVSS / EPSS / KEV / custom weights', 'TrendingUp', 'prioritization', 27, TRUE, false, 'released', NULL),
    ('pentest', 'pentest', 'Penetration Testing', 'Penetration testing campaigns, findings, retests and reports', 'Crosshair', 'validation', 30, TRUE, false, 'released', NULL),
    ('attack_simulation', 'attack-simulation', 'Attack Simulation', 'Breach & Attack Simulation (BAS) — automated adversary emulation to test security controls effectiveness', 'Swords', 'validation', 31, TRUE, false, 'beta', NULL),
    ('control_testing', 'control-testing', 'Control Testing', 'Validate security controls (firewalls, WAF, IDS/IPS) with automated test cases', 'ShieldCheck', 'validation', 32, TRUE, false, 'beta', NULL),
    ('compensating_controls', 'compensating-controls', 'Compensating Controls', 'Controls that reduce finding severity (WAF, EDR, IPS, …)', 'ShieldCheck', 'validation', 33, TRUE, false, 'released', NULL),
    ('remediation', 'remediation', 'Remediation', 'Remediation campaigns that group the fixes for many findings', 'CheckSquare', 'mobilization', 40, TRUE, false, 'released', NULL),
    ('suppressions', 'suppressions', 'Suppressions', 'Finding suppression rules to mute known false positives', 'EyeOff', 'mobilization', 41, TRUE, false, 'released', NULL),
    ('workflows', 'workflows', 'Workflows', 'Trigger-action automation for finding lifecycle (assignment, notification, sync)', 'GitPullRequest', 'mobilization', 43, TRUE, false, 'released', NULL),
    ('reports', 'reports', 'Reports', 'Security reports and analytics', 'FileText', 'insights', 50, TRUE, false, 'released', NULL),
    ('audit', 'audit', 'Audit', 'Audit log for tracking all actions', 'History', 'insights', 51, TRUE, true, 'released', NULL),
    ('ctem_maturity', 'ctem-maturity', 'CTEM Maturity', 'Per-tenant CTEM invariant health — F1-F4, B1-B7, O1-O3', 'ShieldCheck', 'insights', 52, TRUE, false, 'released', NULL),
    ('executive_summary', 'executive-summary', 'Executive Summary', 'Board-ready PDF rollup of risk, breaches, SLAs', 'FileText', 'insights', 53, TRUE, false, 'released', NULL),
    ('mitre_coverage', 'mitre-coverage', 'MITRE Coverage', 'MITRE ATT&CK technique coverage across detections + controls', 'Shield', 'insights', 54, TRUE, false, 'released', NULL),
    ('sbom_export', 'sbom-export', 'SBOM Export', 'Export Software Bill of Materials in CycloneDX / SPDX', 'Download', 'insights', 55, TRUE, false, 'released', NULL),
    ('integrations', 'integrations', 'Integrations', 'Integrations (SCM, Notifications, CI/CD, Ticketing, SIEM)', 'Plug', 'settings', 60, TRUE, true, 'released', NULL),
    ('integrations.scm', 'scm', 'SCM Integrations', 'Source code management integrations', 'GitBranch', 'settings', 1, TRUE, false, 'released', 'integrations'),
    ('integrations.notifications', 'notifications', 'Notification Channels', 'Notification channel integrations', 'Bell', 'settings', 2, TRUE, true, 'released', 'integrations'),
    ('integrations.ticketing', 'ticketing', 'Ticketing', 'Issue tracking integrations', 'Ticket', 'settings', 3, TRUE, false, 'released', 'integrations'),
    ('integrations.cloud', 'cloud', 'Cloud Providers', 'Cloud provider integrations', 'Cloud', 'settings', 4, TRUE, false, 'released', 'integrations'),
    ('integrations.siem', 'siem', 'SIEM', 'SIEM integrations', 'Shield', 'settings', 5, TRUE, false, 'released', 'integrations'),
    ('integrations.scanners', 'scanners', 'Scanners', 'External scanner integrations', 'Search', 'settings', 6, TRUE, false, 'released', 'integrations'),
    ('integrations.api', 'api_int', 'API Integrations', 'API integrations', 'Zap', 'settings', 8, TRUE, false, 'released', 'integrations'),
    ('integrations.pipelines', 'pipelines_int', 'Pipeline Integrations', 'CI/CD pipeline integrations', 'GitPullRequest', 'settings', 9, TRUE, false, 'released', 'integrations'),
    ('sensors', 'sensors', 'Sensors', 'Sensors: scanners, agents and collectors that report to the platform', 'Cpu', 'settings', 61, TRUE, true, 'released', NULL),
    ('team', 'team', 'Team', 'Team members management and invitations', 'Users', 'settings', 62, TRUE, true, 'released', NULL),
    ('groups', 'groups', 'Groups', 'Data scope groups (Teams) for access control', 'UsersCog', 'settings', 63, TRUE, true, 'released', NULL),
    ('roles', 'roles', 'Roles', 'Custom RBAC roles and permission management', 'Shield', 'settings', 64, TRUE, true, 'released', NULL),
    ('settings', 'settings', 'Settings', 'General workspace settings, Risk Scoring, and Module configuration', 'Settings', 'settings', 65, TRUE, true, 'released', NULL),
    ('api_keys', 'api_keys', 'API Keys', 'API key management for programmatic access', 'Key', 'settings', 66, TRUE, true, 'released', NULL),
    ('notification_settings', 'notification_settings', 'Notifications', 'Notification channel settings and delivery configuration', 'Bell', 'settings', 68, TRUE, true, 'released', NULL),
    ('tools', 'tools', 'Tools', 'Security tools and capabilities management', 'Wrench', 'operations', 81, TRUE, false, 'released', NULL),
    ('scan_profiles', 'scan_profiles', 'Scan Profiles', 'Scan configuration profiles', 'Sliders', 'operations', 83, TRUE, false, 'released', NULL),
    ('iocs', 'iocs', 'IOCs', 'Indicators of Compromise', 'Fingerprint', 'operations', 84, TRUE, false, 'released', NULL),
    ('compliance', 'compliance', 'Compliance', 'Compliance frameworks, controls and audit-readiness mappings', 'ClipboardCheck', 'compliance', 90, TRUE, false, 'released', NULL)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug, name = EXCLUDED.name, description = EXCLUDED.description,
    icon = EXCLUDED.icon, category = EXCLUDED.category, display_order = EXCLUDED.display_order,
    is_active = TRUE, is_core = EXCLUDED.is_core, release_status = EXCLUDED.release_status,
    parent_module_id = EXCLUDED.parent_module_id, updated_at = NOW();
-- A row the registry no longer declares is retired: inactive, so no tenant can reach it.
UPDATE modules SET is_active = FALSE, updated_at = NOW()
 WHERE is_active AND id NOT IN ('dashboard', 'assets', 'findings', 'scans', 'attack_surface', 'scope_config', 'business_services', 'ctem_cycles', 'attacker_profiles', 'credentials', 'relationships', 'scanner_templates', 'business_units', 'components', 'template_sources', 'branches', 'crown_jewels', 'scan_workflows', 'threat_model', 'threat_intel', 'exposures', 'ai_triage', 'ai_triage.bulk', 'ai_triage.auto', 'ai_triage.workflow', 'ai_triage.byok', 'ai_triage.agent', 'ai_triage.custom_prompts', 'sla', 'priority_rules', 'risk_analysis', 'business_impact', 'risk_scoring', 'pentest', 'attack_simulation', 'control_testing', 'compensating_controls', 'remediation', 'suppressions', 'workflows', 'reports', 'audit', 'ctem_maturity', 'executive_summary', 'mitre_coverage', 'sbom_export', 'integrations', 'integrations.scm', 'integrations.notifications', 'integrations.ticketing', 'integrations.cloud', 'integrations.siem', 'integrations.scanners', 'integrations.api', 'integrations.pipelines', 'sensors', 'team', 'groups', 'roles', 'settings', 'api_keys', 'notification_settings', 'tools', 'scan_profiles', 'iocs', 'compliance');
-- END module-registry

-- Promote a candidate snapshot under review policy (four-eyes).
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('scans:sources:approve', 'scans', 'Approve Rule Source Snapshots', 'Promote, reject and roll back rule source snapshots', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'scans:sources:approve'
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;
