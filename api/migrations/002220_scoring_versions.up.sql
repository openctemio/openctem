-- Scoring versions and forward-only recompute
-- (api/docs/architecture/scoring-versions.md).
--
-- 1. scoring_changes records every change of a scoring model or of the
--    settings that feed it: one platform row per model version (tenant_id
--    NULL) and one tenant row per change of the risk scoring settings,
--    priority rules or SLA policies. Its id is the version: an asset's risk
--    score and a finding's priority store the id they were computed with,
--    and a value whose id is older than the current one is stale.
-- 2. finding_priority_queue holds the assets whose open findings need a
--    new priority (and SLA deadline). It replaces an in-memory queue that
--    lost its work on restart and was per replica. One row per asset.
-- 3. Triggers queue the work in the same transaction as the change, so no
--    write path can forget it: new findings, a reopen, a severity or asset
--    move, an asset's criticality, exposure or crown-jewel flag, business
--    unit and service membership and criticality, and the tenant settings
--    tables. Closed findings are never queued: they keep the values they
--    had when they were closed.
--
-- Live impact: three nullable columns (no table rewrite), two new tables,
-- AFTER triggers. Existing rows have no version yet; the daily reconcile
-- (and the one at start-up) queues them once.

CREATE TABLE IF NOT EXISTS scoring_changes (
    id            bigserial   PRIMARY KEY,
    -- NULL for a platform model version, which applies to every tenant.
    tenant_id     uuid        REFERENCES tenants (id) ON DELETE CASCADE,
    kind          text        NOT NULL,
    source        text        NOT NULL,
    -- The model version, for platform rows only.
    model_version integer,
    summary       text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_scoring_changes_kind CHECK (kind IN ('asset_risk', 'finding_priority')),
    CONSTRAINT chk_scoring_changes_source CHECK (source IN ('platform_model', 'risk_settings', 'priority_rules', 'sla_policy')),
    CONSTRAINT chk_scoring_changes_platform CHECK (
        (source = 'platform_model') = (tenant_id IS NULL)
        AND (source = 'platform_model') = (model_version IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_scoring_changes_model
    ON scoring_changes (kind, model_version) WHERE source = 'platform_model';
CREATE INDEX IF NOT EXISTS idx_scoring_changes_tenant ON scoring_changes (tenant_id, kind, id);

COMMENT ON TABLE scoring_changes IS
    'Changes of a scoring model (platform rows, tenant_id NULL) or of a tenant''s scoring settings; the id is the scoring version.';

INSERT INTO scoring_changes (tenant_id, kind, source, model_version, summary) VALUES
    (NULL, 'asset_risk', 'platform_model', 2, 'Likelihood and impact asset risk model'),
    (NULL, 'finding_priority', 'platform_model', 1, 'Priority classification P0 to P3')
ON CONFLICT DO NOTHING;

-- The version a process running model p_model may stamp: the newest change
-- of the tenant or the platform, but never at or past a platform model newer
-- than its own. During a rolling deploy an old process thus stamps an older
-- id, and the new model recomputes the row.
CREATE OR REPLACE FUNCTION scoring_version(p_tenant uuid, p_kind text, p_model integer)
RETURNS bigint
LANGUAGE sql STABLE
AS $$
    SELECT COALESCE(MAX(c.id), 0) FROM scoring_changes c
    WHERE c.kind = p_kind
      AND (c.tenant_id = p_tenant OR c.tenant_id IS NULL)
      AND c.id < COALESCE((
          SELECT MIN(n.id) FROM scoring_changes n
          WHERE n.kind = p_kind AND n.tenant_id IS NULL AND n.model_version > p_model
      ), 9223372036854775807)
$$;

COMMENT ON FUNCTION scoring_version(uuid, text, integer) IS
    'Current scoring version (scoring_changes id) of a tenant for a kind, as seen by a process running model p_model.';

ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_version bigint;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_version bigint;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority_scored_at timestamptz;

COMMENT ON COLUMN assets.risk_version IS
    'scoring_changes id the risk score was computed with; NULL = before versions.';
COMMENT ON COLUMN findings.priority_version IS
    'scoring_changes id the priority and SLA deadline were last computed with; NULL = not yet. Frozen once the finding is closed.';
COMMENT ON COLUMN findings.priority_scored_at IS
    'When the finding-priority worker stamped priority_version.';

CREATE TABLE IF NOT EXISTS finding_priority_queue (
    asset_id          uuid        NOT NULL,
    tenant_id         uuid        NOT NULL,
    -- Why the asset is queued; a scoring change wins over other reasons so
    -- its pass can be reported as one summary.
    reason            text        NOT NULL DEFAULT 'finding_change',
    scoring_change_id bigint,
    enqueued_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_finding_priority_queue PRIMARY KEY (asset_id),
    CONSTRAINT fk_finding_priority_queue_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_priority_queue_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_priority_queue_tenant ON finding_priority_queue (tenant_id, enqueued_at);
CREATE INDEX IF NOT EXISTS idx_finding_priority_queue_enqueued ON finding_priority_queue (enqueued_at);

COMMENT ON TABLE finding_priority_queue IS
    'Assets whose open findings wait for the finding-priority worker (priority + SLA); one row per asset.';

-- Statement-level enqueue from a transition table named changed_rows with
-- asset_id, tenant_id and status: assets of the open findings.
CREATE OR REPLACE FUNCTION finding_priority_enqueue_from_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT c.asset_id, c.tenant_id, TG_ARGV[0]
    FROM changed_rows c
    JOIN assets a ON a.id = c.asset_id AND a.tenant_id = c.tenant_id
    WHERE is_open_finding_status(c.status)
    ORDER BY c.asset_id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION finding_priority_enqueue_from_rows() IS
    'Statement trigger: queues the assets of the open findings in changed_rows for the finding-priority worker.';

-- Row-level: a finding reopened, moved to another asset or changed severity.
CREATE OR REPLACE FUNCTION finding_priority_enqueue_finding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.asset_id IS NOT NULL AND is_open_finding_status(NEW.status) THEN
        INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
        SELECT a.id, a.tenant_id, 'finding_change' FROM assets a
        WHERE a.id = NEW.asset_id AND a.tenant_id = NEW.tenant_id
        ON CONFLICT (asset_id) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION finding_priority_enqueue_finding_update() IS
    'Row trigger: queues the asset of an open finding that was reopened, moved or changed severity.';

-- Row-level enqueue of an asset (assets updates).
CREATE OR REPLACE FUNCTION finding_priority_enqueue_asset_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    VALUES (NEW.id, NEW.tenant_id, 'asset_change')
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- Statement-level enqueue of membership rows (asset_id, tenant_id).
CREATE OR REPLACE FUNCTION finding_priority_enqueue_members() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT c.asset_id, c.tenant_id, 'asset_change'
    FROM changed_rows c
    JOIN assets a ON a.id = c.asset_id AND a.tenant_id = c.tenant_id
    ORDER BY c.asset_id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- A business unit's criticality or parent changed: every unit member of the
-- tenant (units are few and nest).
CREATE OR REPLACE FUNCTION finding_priority_enqueue_business_unit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT bua.asset_id, bua.tenant_id, 'asset_change'
    FROM business_unit_assets bua
    WHERE bua.tenant_id = NEW.tenant_id
    ORDER BY bua.asset_id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION finding_priority_enqueue_business_service() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT bsa.asset_id, bsa.tenant_id, 'asset_change'
    FROM business_service_assets bsa
    WHERE bsa.tenant_id = NEW.tenant_id AND bsa.service_id = NEW.id
    ORDER BY bsa.asset_id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- Records a tenant scoring change and queues its scope in the same
-- transaction. finding_priority: the assets of the tenant's open findings;
-- asset_risk: every live asset of the tenant.
CREATE OR REPLACE FUNCTION scoring_record_tenant_change(p_tenant uuid, p_kind text, p_source text, p_summary text)
RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant) THEN
        RETURN NULL; -- system rows (the zero tenant) change only with a platform model
    END IF;
    INSERT INTO scoring_changes (tenant_id, kind, source, summary)
    VALUES (p_tenant, p_kind, p_source, p_summary)
    RETURNING id INTO v_id;

    IF p_kind = 'finding_priority' THEN
        INSERT INTO finding_priority_queue (asset_id, tenant_id, reason, scoring_change_id)
        SELECT DISTINCT f.asset_id, f.tenant_id, 'scoring_change', v_id
        FROM findings f
        JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
        WHERE f.tenant_id = p_tenant AND is_open_finding_status(f.status)
        ORDER BY f.asset_id
        ON CONFLICT (asset_id) DO UPDATE
            SET reason = 'scoring_change', scoring_change_id = EXCLUDED.scoring_change_id,
                enqueued_at = LEAST(finding_priority_queue.enqueued_at, EXCLUDED.enqueued_at);
    ELSE
        INSERT INTO asset_risk_queue (asset_id, tenant_id)
        SELECT a.id, a.tenant_id FROM assets a
        WHERE a.tenant_id = p_tenant AND a.deleted_at IS NULL
        ORDER BY a.id
        ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
            WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    END IF;
    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION scoring_record_tenant_change(uuid, text, text, text) IS
    'Records a tenant scoring change in scoring_changes and queues the assets it affects.';

-- priority_override_rules: a statement that changed what a rule matches or
-- decides (not its name or description) is one change per tenant.
CREATE OR REPLACE FUNCTION scoring_rules_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    t uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        FOR t IN SELECT DISTINCT tenant_id FROM new_rows WHERE is_active LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'priority_rules', 'Priority rule added');
        END LOOP;
    ELSIF TG_OP = 'DELETE' THEN
        FOR t IN SELECT DISTINCT tenant_id FROM old_rows WHERE is_active LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'priority_rules', 'Priority rule deleted');
        END LOOP;
    ELSE
        FOR t IN
            SELECT DISTINCT n.tenant_id FROM new_rows n JOIN old_rows o ON o.id = n.id
            WHERE n.priority_class IS DISTINCT FROM o.priority_class
               OR n.conditions IS DISTINCT FROM o.conditions
               OR n.is_active IS DISTINCT FROM o.is_active
               OR (n.is_active AND n.evaluation_order IS DISTINCT FROM o.evaluation_order)
        LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'priority_rules', 'Priority rules changed');
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$;

-- sla_policies: deadlines are computed with the priority, in the same pass.
CREATE OR REPLACE FUNCTION scoring_sla_policies_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    t uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        FOR t IN SELECT DISTINCT tenant_id FROM new_rows LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'sla_policy', 'SLA policy added');
        END LOOP;
    ELSIF TG_OP = 'DELETE' THEN
        FOR t IN SELECT DISTINCT tenant_id FROM old_rows LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'sla_policy', 'SLA policy deleted');
        END LOOP;
    ELSE
        FOR t IN
            SELECT DISTINCT n.tenant_id FROM new_rows n JOIN old_rows o ON o.id = n.id
            WHERE (n.asset_id, n.is_default, n.is_active, n.critical_days, n.high_days, n.medium_days,
                   n.low_days, n.info_days, n.p0_days, n.p1_days, n.p2_days, n.p3_days,
                   n.warning_threshold_percent)
                  IS DISTINCT FROM
                  (o.asset_id, o.is_default, o.is_active, o.critical_days, o.high_days, o.medium_days,
                   o.low_days, o.info_days, o.p0_days, o.p1_days, o.p2_days, o.p3_days,
                   o.warning_threshold_percent)
        LOOP
            PERFORM scoring_record_tenant_change(t, 'finding_priority', 'sla_policy', 'SLA policy changed');
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$;

-- tenants.settings: the risk scoring section feeds the asset risk score;
-- its floor_unowned_at_p2 key feeds finding priority.
CREATE OR REPLACE FUNCTION scoring_tenant_settings_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.settings->'risk_scoring') - 'floor_unowned_at_p2'
        IS DISTINCT FROM (NEW.settings->'risk_scoring') - 'floor_unowned_at_p2' THEN
        PERFORM scoring_record_tenant_change(NEW.id, 'asset_risk', 'risk_settings', 'Risk scoring settings changed');
    END IF;
    IF COALESCE((OLD.settings->'risk_scoring'->>'floor_unowned_at_p2')::boolean, false)
        IS DISTINCT FROM COALESCE((NEW.settings->'risk_scoring'->>'floor_unowned_at_p2')::boolean, false) THEN
        PERFORM scoring_record_tenant_change(NEW.id, 'finding_priority', 'risk_settings', 'Ownership floor changed');
    END IF;
    RETURN NULL;
END;
$$;

-- findings
DROP TRIGGER IF EXISTS trg_findings_priority_insert ON findings;
CREATE TRIGGER trg_findings_priority_insert
    AFTER INSERT ON findings
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_from_rows('new_finding');

-- priority_class and the SLA columns are not watched: the worker writes them.
DROP TRIGGER IF EXISTS trg_findings_priority_update ON findings;
CREATE TRIGGER trg_findings_priority_update
    AFTER UPDATE OF status, severity, asset_id ON findings
    FOR EACH ROW
    WHEN ((NOT is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status))
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id)
    EXECUTE FUNCTION finding_priority_enqueue_finding_update();

-- assets
DROP TRIGGER IF EXISTS trg_assets_priority_update ON assets;
CREATE TRIGGER trg_assets_priority_update
    AFTER UPDATE OF criticality, exposure, is_crown_jewel, deleted_at ON assets
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.exposure IS DISTINCT FROM NEW.exposure
       OR OLD.is_crown_jewel IS DISTINCT FROM NEW.is_crown_jewel
       OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL))
    EXECUTE FUNCTION finding_priority_enqueue_asset_row();

-- business context
DROP TRIGGER IF EXISTS trg_business_unit_assets_priority_insert ON business_unit_assets;
CREATE TRIGGER trg_business_unit_assets_priority_insert
    AFTER INSERT ON business_unit_assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_members();

DROP TRIGGER IF EXISTS trg_business_unit_assets_priority_delete ON business_unit_assets;
CREATE TRIGGER trg_business_unit_assets_priority_delete
    AFTER DELETE ON business_unit_assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_members();

DROP TRIGGER IF EXISTS trg_business_service_assets_priority_insert ON business_service_assets;
CREATE TRIGGER trg_business_service_assets_priority_insert
    AFTER INSERT ON business_service_assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_members();

DROP TRIGGER IF EXISTS trg_business_service_assets_priority_delete ON business_service_assets;
CREATE TRIGGER trg_business_service_assets_priority_delete
    AFTER DELETE ON business_service_assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_members();

DROP TRIGGER IF EXISTS trg_business_units_priority_update ON business_units;
CREATE TRIGGER trg_business_units_priority_update
    AFTER UPDATE OF criticality, parent_id ON business_units
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.parent_id IS DISTINCT FROM NEW.parent_id)
    EXECUTE FUNCTION finding_priority_enqueue_business_unit();

DROP TRIGGER IF EXISTS trg_business_services_priority_update ON business_services;
CREATE TRIGGER trg_business_services_priority_update
    AFTER UPDATE OF criticality ON business_services
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality)
    EXECUTE FUNCTION finding_priority_enqueue_business_service();

-- settings
DROP TRIGGER IF EXISTS trg_priority_rules_scoring_insert ON priority_override_rules;
CREATE TRIGGER trg_priority_rules_scoring_insert
    AFTER INSERT ON priority_override_rules
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_rules_changed();

DROP TRIGGER IF EXISTS trg_priority_rules_scoring_update ON priority_override_rules;
CREATE TRIGGER trg_priority_rules_scoring_update
    AFTER UPDATE ON priority_override_rules
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_rules_changed();

DROP TRIGGER IF EXISTS trg_priority_rules_scoring_delete ON priority_override_rules;
CREATE TRIGGER trg_priority_rules_scoring_delete
    AFTER DELETE ON priority_override_rules
    REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_rules_changed();

DROP TRIGGER IF EXISTS trg_sla_policies_scoring_insert ON sla_policies;
CREATE TRIGGER trg_sla_policies_scoring_insert
    AFTER INSERT ON sla_policies
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_sla_policies_changed();

DROP TRIGGER IF EXISTS trg_sla_policies_scoring_update ON sla_policies;
CREATE TRIGGER trg_sla_policies_scoring_update
    AFTER UPDATE ON sla_policies
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_sla_policies_changed();

DROP TRIGGER IF EXISTS trg_sla_policies_scoring_delete ON sla_policies;
CREATE TRIGGER trg_sla_policies_scoring_delete
    AFTER DELETE ON sla_policies
    REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION scoring_sla_policies_changed();

DROP TRIGGER IF EXISTS trg_tenants_scoring_settings ON tenants;
CREATE TRIGGER trg_tenants_scoring_settings
    AFTER UPDATE OF settings ON tenants
    FOR EACH ROW
    WHEN (OLD.settings->'risk_scoring' IS DISTINCT FROM NEW.settings->'risk_scoring')
    EXECUTE FUNCTION scoring_tenant_settings_changed();
