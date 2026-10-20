-- Priority recompute triggers for the remaining classifier inputs.
-- The finding-priority worker scores an asset's open findings from the
-- finding (CVE, CVSS, exposure flags, data exposure, compliance), the asset
-- (criticality, exposure, crown jewel, CIA impact ratings) and its owners.
-- Until now only status, severity and asset_id of a finding and four asset
-- columns queued a recompute, so the other inputs waited for the daily
-- reconcile. Trigger DDL only: no backfill, nothing is rewritten.
--
-- Not watched: is_reachable, reachable_from_count, epss_score, epss_percentile,
-- is_in_kev and kev_due_date are written by the worker itself (derived), so
-- watching them would re-queue every pass.
-- Inputs covered elsewhere: KEV and EPSS by the threat-intel refresh, business
-- unit and service membership and criticality by their own triggers, tenant
-- settings and SLA / priority rules by the scoring-change triggers.

-- findings: any finding-level classifier input.
DROP TRIGGER IF EXISTS trg_findings_priority_update ON findings;
CREATE TRIGGER trg_findings_priority_update
    AFTER UPDATE OF status, severity, asset_id, cve_id, vulnerability_id, cvss_score,
                    is_internet_accessible, is_network_accessible,
                    exposure_vector, data_exposure_risk, compliance_impact ON findings
    FOR EACH ROW
    WHEN ((NOT is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status))
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.cve_id IS DISTINCT FROM NEW.cve_id
       OR OLD.vulnerability_id IS DISTINCT FROM NEW.vulnerability_id
       OR OLD.cvss_score IS DISTINCT FROM NEW.cvss_score
       OR OLD.is_internet_accessible IS DISTINCT FROM NEW.is_internet_accessible
       OR OLD.is_network_accessible IS DISTINCT FROM NEW.is_network_accessible
       OR OLD.exposure_vector IS DISTINCT FROM NEW.exposure_vector
       OR OLD.data_exposure_risk IS DISTINCT FROM NEW.data_exposure_risk
       OR OLD.compliance_impact IS DISTINCT FROM NEW.compliance_impact)
    EXECUTE FUNCTION finding_priority_enqueue_finding_update();

-- assets: the CIA impact ratings raise the impact signal.
DROP TRIGGER IF EXISTS trg_assets_priority_update ON assets;
CREATE TRIGGER trg_assets_priority_update
    AFTER UPDATE OF criticality, exposure, is_crown_jewel, deleted_at,
                    impact_confidentiality, impact_integrity, impact_availability ON assets
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.exposure IS DISTINCT FROM NEW.exposure
       OR OLD.is_crown_jewel IS DISTINCT FROM NEW.is_crown_jewel
       OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL)
       OR OLD.impact_confidentiality IS DISTINCT FROM NEW.impact_confidentiality
       OR OLD.impact_integrity IS DISTINCT FROM NEW.impact_integrity
       OR OLD.impact_availability IS DISTINCT FROM NEW.impact_availability)
    EXECUTE FUNCTION finding_priority_enqueue_asset_row();

-- asset_owners: an asset gaining its first owner or losing its last one moves
-- the ownership floor. Any owner row change queues the asset when it has an
-- open finding (the worker re-reads owner presence; user and group owners
-- both count), which is simpler than testing for the first or last owner.
-- asset_owners has no tenant column, so the tenant comes from the asset.
CREATE OR REPLACE FUNCTION finding_priority_enqueue_owners() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT a.id, a.tenant_id, 'asset_change'
    FROM changed_rows c
    JOIN assets a ON a.id = c.asset_id
    WHERE EXISTS (SELECT 1 FROM findings f
                  WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND is_open_finding_status(f.status))
    ORDER BY a.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION finding_priority_enqueue_owners() IS
    'Statement trigger: queues the assets of the owner rows in changed_rows that have open findings.';

-- An owner row moved to another asset: both assets.
CREATE OR REPLACE FUNCTION finding_priority_enqueue_owner_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
    SELECT DISTINCT a.id, a.tenant_id, 'asset_change'
    FROM assets a
    WHERE a.id IN (OLD.asset_id, NEW.asset_id)
      AND EXISTS (SELECT 1 FROM findings f
                  WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND is_open_finding_status(f.status))
    ORDER BY a.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_asset_owners_priority_insert ON asset_owners;
CREATE TRIGGER trg_asset_owners_priority_insert
    AFTER INSERT ON asset_owners
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_owners();

DROP TRIGGER IF EXISTS trg_asset_owners_priority_delete ON asset_owners;
CREATE TRIGGER trg_asset_owners_priority_delete
    AFTER DELETE ON asset_owners
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION finding_priority_enqueue_owners();

DROP TRIGGER IF EXISTS trg_asset_owners_priority_update ON asset_owners;
CREATE TRIGGER trg_asset_owners_priority_update
    AFTER UPDATE OF asset_id, user_id, group_id ON asset_owners
    FOR EACH ROW
    WHEN (OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.user_id IS DISTINCT FROM NEW.user_id
       OR OLD.group_id IS DISTINCT FROM NEW.group_id)
    EXECUTE FUNCTION finding_priority_enqueue_owner_row();
