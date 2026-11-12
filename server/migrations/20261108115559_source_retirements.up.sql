-- Retire an import source (docs/architecture/source-retirement.md).
--
-- source_retirements: one row per retirement of a source (a sensor's tool,
-- an upload tool, a connector source name). While a row is not restored,
-- ingest refuses the source's reports (counted on the receipt as
-- source_retired) and its findings only it reported are archived (resolved,
-- closure reason obsolete_source, resolution source_retired).
--
-- source_retirement_findings: the journal of the findings a retirement
-- archived, with the status each had, so "use this source again" restores
-- exactly that set.
--
-- source_retirement_matches: whether a sighting belongs to a retired source;
-- the one definition of "this source" for the preview, the archive and the
-- corroboration check.
--
-- Permission findings:sources:retire goes to the owner and administrator
-- roles.
--
-- Live impact: two new empty tables, one SQL function, one trigger on the
-- new table, one permission row and two role_permissions rows. No existing
-- table is rewritten or locked.

CREATE TABLE IF NOT EXISTS source_retirements (
    id              uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind            varchar(16)  NOT NULL,
    sensor_id       uuid,
    sender          varchar(128) NOT NULL DEFAULT '',
    tool            varchar(100) NOT NULL DEFAULT '',
    integration_id  uuid,
    label           varchar(200) NOT NULL DEFAULT '',
    mode            varchar(16)  NOT NULL,
    severities      text[]       NOT NULL DEFAULT '{}',
    include_engaged boolean      NOT NULL DEFAULT false,
    state           varchar(16)  NOT NULL,
    reason          varchar(500) NOT NULL,
    planned_count   integer      NOT NULL DEFAULT 0,
    archived_count  integer      NOT NULL DEFAULT 0,
    restored_count  integer      NOT NULL DEFAULT 0,
    changed_count   integer      NOT NULL DEFAULT 0,
    retired_by      uuid,
    retired_at      timestamptz  NOT NULL DEFAULT now(),
    restored_by     uuid,
    restore_reason  varchar(500) NOT NULL DEFAULT '',
    restored_at     timestamptz,
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_source_retirements PRIMARY KEY (id),
    CONSTRAINT ux_source_retirements_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_source_retirements_kind CHECK (kind IN ('sensor_tool', 'upload', 'connector')),
    CONSTRAINT chk_source_retirements_shape CHECK (CASE kind
        WHEN 'sensor_tool' THEN sensor_id IS NOT NULL AND tool <> '' AND sender = ''
        WHEN 'upload' THEN sensor_id IS NULL AND tool <> '' AND sender = ''
        ELSE sensor_id IS NULL AND sender <> '' AND tool = ''
    END),
    CONSTRAINT chk_source_retirements_mode CHECK (mode IN ('archive', 'keep_open')),
    CONSTRAINT chk_source_retirements_state CHECK (state IN ('applying', 'active', 'restoring', 'restored')),
    CONSTRAINT chk_source_retirements_restored CHECK ((state = 'restored') = (restored_at IS NOT NULL)),
    CONSTRAINT chk_source_retirements_counts CHECK (planned_count >= 0 AND archived_count >= 0
        AND restored_count >= 0 AND changed_count >= 0)
);

COMMENT ON TABLE source_retirements IS
    'Retired import sources: while not restored, ingest refuses the source (receipt outcome source_retired) and the findings only it reported are archived as source retired. One live row per source.';
COMMENT ON COLUMN source_retirements.kind IS
    'sensor_tool (the tenant''s sensor and a tool), upload (an uploaded tool), connector (a server-side connector source name).';
COMMENT ON COLUMN source_retirements.integration_id IS
    'The connector integration the source was retired from (display only; the selector is sensor_id + tool). No FK: the record outlives the integration.';
COMMENT ON COLUMN source_retirements.state IS
    'applying (archiving in batches), active, restoring (restoring in batches), restored.';

-- One live retirement per source: a second apply returns it (idempotent).
CREATE UNIQUE INDEX IF NOT EXISTS ux_source_retirements_live
    ON source_retirements (tenant_id, kind, sensor_id, sender, tool) NULLS NOT DISTINCT
    WHERE state <> 'restored';
-- The controller resumes unfinished batches.
CREATE INDEX IF NOT EXISTS idx_source_retirements_pending
    ON source_retirements (state, updated_at) WHERE state IN ('applying', 'restoring');

CREATE TABLE IF NOT EXISTS source_retirement_findings (
    tenant_id      uuid         NOT NULL,
    retirement_id  uuid         NOT NULL,
    finding_id     uuid         NOT NULL,
    prior_status   varchar(30)  NOT NULL,
    archived_at    timestamptz  NOT NULL,
    restored_at    timestamptz,
    restore_outcome varchar(16),
    CONSTRAINT pk_source_retirement_findings PRIMARY KEY (tenant_id, retirement_id, finding_id),
    CONSTRAINT fk_source_retirement_findings_retirement FOREIGN KEY (tenant_id, retirement_id)
        REFERENCES source_retirements (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_source_retirement_findings_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_source_retirement_findings_prior CHECK (prior_status IN ('new', 'confirmed')),
    CONSTRAINT chk_source_retirement_findings_outcome CHECK (
        (restored_at IS NULL AND restore_outcome IS NULL)
        OR (restored_at IS NOT NULL AND restore_outcome IN ('restored', 'changed')))
);
CREATE INDEX IF NOT EXISTS idx_source_retirement_findings_finding
    ON source_retirement_findings (tenant_id, finding_id);
COMMENT ON TABLE source_retirement_findings IS
    'Journal of the findings a source retirement archived, with their prior status, so restoring the source restores exactly that set; a finding changed since is left as is (restore_outcome changed).';

-- Whether a sighting (channel, sensor, sender, tool) belongs to a retired
-- source (kind, sensor, sender, tool); tool names compare without case, as
-- ingest compares them. Inlined by the planner.
CREATE OR REPLACE FUNCTION source_retirement_matches(
    r_kind text, r_sensor uuid, r_sender text, r_tool text,
    s_channel text, s_sensor uuid, s_sender text, s_tool text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE r_kind
        WHEN 'sensor_tool' THEN s_sensor IS NOT NULL AND s_sensor = r_sensor AND lower(s_tool) = lower(r_tool)
        WHEN 'upload' THEN s_channel = 'upload' AND lower(s_tool) = lower(r_tool)
        WHEN 'connector' THEN s_channel = 'connector' AND s_sender = r_sender
        ELSE false
    END
$$;

-- A retirement changes what ingest accepts: bump the tenant's ingest policy
-- version so every worker reloads its snapshot.
DROP TRIGGER IF EXISTS trg_source_retirements_policy_version ON source_retirements;
CREATE TRIGGER trg_source_retirements_policy_version
    AFTER INSERT OR UPDATE OF state OR DELETE ON source_retirements
    FOR EACH ROW EXECUTE FUNCTION bump_ingest_policy_version();

-- Row-level security policies in shadow mode, like the other tenant tables.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['source_retirements', 'source_retirement_findings'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('findings:sources:retire', 'findings', 'Retire Import Sources',
     'Stop using an import source: block its data and archive the findings only it reported, and restore it', true, now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, 'findings:sources:retire', now()
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = 'findings:sources:retire');
