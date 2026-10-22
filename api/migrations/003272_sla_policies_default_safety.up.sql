-- The tenant default SLA policy is protected at the database:
--   * at most one tenant-wide default per tenant (partial unique index),
--   * a default is active (an inactive default used to keep governing),
--   * remediation windows are inside the range the service accepts.
--
-- Data first, so the constraints below cannot fail on a populated table. If a
-- tenant has several tenant-wide defaults, the oldest ACTIVE one stays (ties
-- by id) and the others are unset; an inactive default is unset too. Only the
-- is_default flag changes: no tenant's windows are rewritten. Unsetting a
-- default can only move findings to the platform windows; deadlines of open
-- findings are tighten-only, so none becomes later.
UPDATE sla_policies p
SET is_default = false, updated_at = now()
FROM (
    SELECT id,
           row_number() OVER (PARTITION BY tenant_id ORDER BY is_active DESC, created_at ASC, id ASC) AS rn
    FROM sla_policies
    WHERE is_default AND asset_id IS NULL
) r
WHERE p.id = r.id AND (r.rn > 1 OR NOT p.is_active);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sla_policies_tenant_default
    ON sla_policies (tenant_id)
    WHERE is_default AND asset_id IS NULL;

ALTER TABLE sla_policies
    ADD CONSTRAINT chk_sla_policies_default_active
    CHECK (NOT (is_default AND asset_id IS NULL) OR is_active) NOT VALID;
ALTER TABLE sla_policies VALIDATE CONSTRAINT chk_sla_policies_default_active;

-- Same bounds as the service: critical..low 1..365 days, info 0 (no SLA)..365.
ALTER TABLE sla_policies
    ADD CONSTRAINT chk_sla_policies_severity_days
    CHECK (critical_days BETWEEN 1 AND 365
       AND high_days BETWEEN 1 AND 365
       AND medium_days BETWEEN 1 AND 365
       AND low_days BETWEEN 1 AND 365
       AND info_days BETWEEN 0 AND 365) NOT VALID;
ALTER TABLE sla_policies VALIDATE CONSTRAINT chk_sla_policies_severity_days;
