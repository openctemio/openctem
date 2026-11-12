-- Asset risk score freshness (api/docs/architecture/asset-risk-score.md).
--
-- An asset's risk_score was written only by the manual recalculation and by
-- attribute reconciliation, so findings that arrived by CI upload, sensor
-- ingest, import, bulk triage or auto-resolve never moved it: a repository
-- with 81 open findings still showed 0.
--
-- Every change to an input of the score now marks the asset in
-- asset_risk_queue, from triggers, so no write path can forget it. The queue
-- holds one row per asset (the primary key coalesces a burst: a 100k-finding
-- import queues each touched asset once), and the asset-risk-score worker
-- claims rows in batches and rescores them per tenant.
--
-- assets.risk_scored_at is when the current score was computed; NULL means
-- the asset has never been scored, which the console shows as "Not yet
-- scored" instead of a score of 0.
--
-- Live impact: one nullable column (no table rewrite), a new table, and
-- AFTER triggers on findings, assets and the business-context membership
-- tables. Every live asset is queued once at the end, which rescores the
-- whole inventory in the background after deploy.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_scored_at timestamptz;

COMMENT ON COLUMN assets.risk_scored_at IS
    'When risk_score was last computed; NULL = never scored.';

-- Both foreign keys cascade, so deleting an asset or a tenant removes its
-- rows. The trigger functions queue only assets that still exist: a cascaded
-- finding delete fires while its asset is being deleted.
CREATE TABLE IF NOT EXISTS asset_risk_queue (
    asset_id    uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    -- Claimed oldest first. The daily reconcile queues with a later due time
    -- so event-driven rows go ahead of it.
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_risk_queue PRIMARY KEY (asset_id),
    CONSTRAINT fk_asset_risk_queue_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_risk_queue_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_risk_queue_enqueued ON asset_risk_queue (enqueued_at);
CREATE INDEX IF NOT EXISTS idx_asset_risk_queue_tenant ON asset_risk_queue (tenant_id);

COMMENT ON TABLE asset_risk_queue IS
    'Assets whose risk score inputs changed and that wait for the asset-risk-score worker; one row per asset.';

-- Statement-level enqueue from a transition table named changed_rows that
-- has asset_id and tenant_id columns. ORDER BY keeps the lock order stable
-- between concurrent statements.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_from_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT DISTINCT c.asset_id, c.tenant_id
    FROM changed_rows c
    JOIN assets a ON a.id = c.asset_id AND a.tenant_id = c.tenant_id
    ORDER BY c.asset_id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_from_rows() IS
    'Statement trigger: queues the distinct (asset_id, tenant_id) of the changed_rows transition table for risk rescoring.';

-- Row-level enqueue for a finding update that changed a score input. A
-- finding moved to another asset rescores both.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_finding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.asset_id IS NOT NULL THEN
        INSERT INTO asset_risk_queue (asset_id, tenant_id)
        SELECT a.id, a.tenant_id FROM assets a WHERE a.id = NEW.asset_id AND a.tenant_id = NEW.tenant_id
        ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
            WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    END IF;
    IF OLD.asset_id IS NOT NULL AND OLD.asset_id IS DISTINCT FROM NEW.asset_id THEN
        INSERT INTO asset_risk_queue (asset_id, tenant_id)
        SELECT a.id, a.tenant_id FROM assets a WHERE a.id = OLD.asset_id AND a.tenant_id = OLD.tenant_id
        ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
            WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    END IF;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_finding_update() IS
    'Row trigger: queues the asset (and the previous asset) of a finding whose risk inputs changed.';

-- Row-level enqueue of the asset itself (assets updates).
CREATE OR REPLACE FUNCTION asset_risk_enqueue_asset_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id) VALUES (NEW.id, NEW.tenant_id)
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_asset_row() IS
    'Row trigger: queues an asset whose criticality, exposure or data context changed.';

-- A business unit's criticality or parent changed: its members, and the
-- members of every unit below it, may score differently. Units are few, so
-- every member of the tenant's units is queued.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_business_unit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT DISTINCT bua.asset_id, bua.tenant_id
    FROM business_unit_assets bua
    WHERE bua.tenant_id = NEW.tenant_id
    ORDER BY bua.asset_id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_business_unit() IS
    'Row trigger: queues the business-unit members of the tenant after a unit''s criticality or parent changed.';

-- A business service's criticality changed: queue the assets that power it.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_business_service() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT DISTINCT bsa.asset_id, bsa.tenant_id
    FROM business_service_assets bsa
    WHERE bsa.tenant_id = NEW.tenant_id AND bsa.service_id = NEW.id
    ORDER BY bsa.asset_id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_business_service() IS
    'Row trigger: queues the assets of a business service whose criticality changed.';

-- Statement-level enqueue of newly inserted assets.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_new_assets() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT n.id, n.tenant_id
    FROM new_assets n
    WHERE n.tenant_id IS NOT NULL
    ORDER BY n.id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_new_assets() IS
    'Statement trigger: queues newly inserted assets for their first risk score.';

-- findings: new, deleted, and updated findings whose score inputs changed.
DROP TRIGGER IF EXISTS trg_findings_asset_risk_insert ON findings;
CREATE TRIGGER trg_findings_asset_risk_insert
    AFTER INSERT ON findings
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_findings_asset_risk_delete ON findings;
CREATE TRIGGER trg_findings_asset_risk_delete
    AFTER DELETE ON findings
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_findings_asset_risk_update ON findings;
CREATE TRIGGER trg_findings_asset_risk_update
    AFTER UPDATE OF status, severity, asset_id, branch_only, epss_score, is_in_kev,
        exploit_available, is_reachable, vex_status ON findings
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.branch_only IS DISTINCT FROM NEW.branch_only
       OR OLD.epss_score IS DISTINCT FROM NEW.epss_score
       OR OLD.is_in_kev IS DISTINCT FROM NEW.is_in_kev
       OR OLD.exploit_available IS DISTINCT FROM NEW.exploit_available
       OR OLD.is_reachable IS DISTINCT FROM NEW.is_reachable
       OR OLD.vex_status IS DISTINCT FROM NEW.vex_status)
    EXECUTE FUNCTION asset_risk_enqueue_finding_update();

-- assets: a new asset is scored once; an edit of a score input rescores it.
-- risk_score and risk_scored_at are deliberately not watched (the worker
-- writes them).
DROP TRIGGER IF EXISTS trg_assets_risk_insert ON assets;
CREATE TRIGGER trg_assets_risk_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS new_assets
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_new_assets();

DROP TRIGGER IF EXISTS trg_assets_risk_update ON assets;
CREATE TRIGGER trg_assets_risk_update
    AFTER UPDATE OF criticality, exposure, is_internet_accessible, pii_data_exposed,
        phi_data_exposed, data_classification, compliance_scope, is_crown_jewel,
        deleted_at ON assets
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.exposure IS DISTINCT FROM NEW.exposure
       OR OLD.is_internet_accessible IS DISTINCT FROM NEW.is_internet_accessible
       OR OLD.pii_data_exposed IS DISTINCT FROM NEW.pii_data_exposed
       OR OLD.phi_data_exposed IS DISTINCT FROM NEW.phi_data_exposed
       OR OLD.data_classification IS DISTINCT FROM NEW.data_classification
       OR OLD.compliance_scope IS DISTINCT FROM NEW.compliance_scope
       OR OLD.is_crown_jewel IS DISTINCT FROM NEW.is_crown_jewel
       OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL))
    EXECUTE FUNCTION asset_risk_enqueue_asset_row();

-- Business context: membership changes and criticality edits.
DROP TRIGGER IF EXISTS trg_business_unit_assets_risk_insert ON business_unit_assets;
CREATE TRIGGER trg_business_unit_assets_risk_insert
    AFTER INSERT ON business_unit_assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_business_unit_assets_risk_delete ON business_unit_assets;
CREATE TRIGGER trg_business_unit_assets_risk_delete
    AFTER DELETE ON business_unit_assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_business_service_assets_risk_insert ON business_service_assets;
CREATE TRIGGER trg_business_service_assets_risk_insert
    AFTER INSERT ON business_service_assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_business_service_assets_risk_delete ON business_service_assets;
CREATE TRIGGER trg_business_service_assets_risk_delete
    AFTER DELETE ON business_service_assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_from_rows();

DROP TRIGGER IF EXISTS trg_business_units_risk_update ON business_units;
CREATE TRIGGER trg_business_units_risk_update
    AFTER UPDATE OF criticality, parent_id ON business_units
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.parent_id IS DISTINCT FROM NEW.parent_id)
    EXECUTE FUNCTION asset_risk_enqueue_business_unit();

DROP TRIGGER IF EXISTS trg_business_services_risk_update ON business_services;
CREATE TRIGGER trg_business_services_risk_update
    AFTER UPDATE OF criticality ON business_services
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality)
    EXECUTE FUNCTION asset_risk_enqueue_business_service();

-- Backfill: queue every live asset once. Scores written before this
-- migration were often never recomputed (or never computed at all); the
-- worker rescores them in batches after deploy.
INSERT INTO asset_risk_queue (asset_id, tenant_id)
SELECT a.id, a.tenant_id
FROM assets a
WHERE a.deleted_at IS NULL AND a.tenant_id IS NOT NULL
ON CONFLICT (asset_id) DO NOTHING;
