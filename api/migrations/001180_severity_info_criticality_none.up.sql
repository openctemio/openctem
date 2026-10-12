-- Informational severity and "not rated" asset criticality.
--
-- 1. assets.criticality accepts 'none' (Not rated). The asset domain, the API
--    validator and the risk-scoring settings already accept it, but this CHECK
--    did not, so saving an asset as Not rated failed with a constraint error.
-- 2. Informational findings (severity info, or none = CVSS 0.0) get no SLA by
--    default. sla_policies.info_days = 0 now means "no SLA for informational
--    findings"; a tenant opts in by setting a positive value.
--    - new policies default to 0;
--    - policies still on a shipped default info window (90 or 365 days) move
--      to 0. A tenant that wants an info SLA sets it again in the policy;
--    - open informational findings whose effective policy (the asset's own
--      active policy, else the tenant default; no policy = no SLA) now has no
--      info SLA lose their deadline and become not_applicable, so they stop
--      counting towards SLA breaches and escalations. Closed findings keep
--      their history.
--
-- Safe on populated tables: the new CHECK is looser than the old one and is
-- added NOT VALID then validated (no long exclusive lock); the backfills touch
-- only sla_policies rows on the old defaults and open informational findings
-- that carry a deadline.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_criticality;
ALTER TABLE assets ADD CONSTRAINT chk_assets_criticality CHECK (
    criticality IN ('critical', 'high', 'medium', 'low', 'none')
) NOT VALID;
ALTER TABLE assets VALIDATE CONSTRAINT chk_assets_criticality;

ALTER TABLE sla_policies ALTER COLUMN info_days SET DEFAULT 0;

UPDATE sla_policies SET info_days = 0 WHERE info_days IN (90, 365);

UPDATE findings f
   SET sla_deadline = NULL,
       sla_status = 'not_applicable'
 WHERE f.severity IN ('info', 'none')
   AND f.sla_deadline IS NOT NULL
   AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'verified', 'accepted_risk')
   AND COALESCE((
           SELECT p.info_days
             FROM sla_policies p
            WHERE p.tenant_id = f.tenant_id
              AND p.is_active
              AND (p.asset_id = f.asset_id OR (p.asset_id IS NULL AND p.is_default))
            ORDER BY p.asset_id NULLS LAST
            LIMIT 1
       ), 0) = 0;
