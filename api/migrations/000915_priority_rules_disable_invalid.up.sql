-- Priority override rules: switch off every active rule that cannot be valid
-- (owner decision B17, research 23 SB-04).
--
-- The create endpoint used to store a rule without validating it. A rule with
-- an empty condition list matched EVERY finding, and the first matching rule
-- wins, so one such rule re-classed the whole tenant (KEV findings on crown
-- jewels included) and stretched their SLA deadlines. A rule with an unknown
-- field or operator, or a null value, never matched and only looked active.
-- From this release every write is validated; this migration deals with the
-- rows already stored.
--
-- What it does:
--   1. records each rule it switches off in priority_rule_safety_report
--      (tenant, rule, name, class, reason, the conditions as stored), which an
--      operator can read before telling the organization;
--   2. sets those rules is_active = false. Nothing is deleted: an owner can fix
--      the conditions and enable the rule again (the API refuses to enable it
--      unchanged);
--   3. raises a NOTICE with the count, so the migration log shows the impact.
--
-- Safe on live data: priority_override_rules holds a few rows per tenant; the
-- statements are short. The classifier picks the change up on its next sweep.

CREATE TABLE IF NOT EXISTS priority_rule_safety_report (
    rule_id        UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name      VARCHAR(100) NOT NULL,
    priority_class VARCHAR(2) NOT NULL,
    reason         TEXT NOT NULL,
    conditions     JSONB,
    disabled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE priority_rule_safety_report IS
    'Priority override rules migration 000915 switched off because their conditions could not be valid (B17). Read-only record for operators.';

WITH invalid AS (
    SELECT r.id, r.tenant_id, r.name, r.priority_class, r.conditions,
           CASE
               WHEN r.conditions IS NULL OR jsonb_typeof(r.conditions) <> 'array'
                   THEN 'conditions are not a list'
               WHEN jsonb_array_length(r.conditions) = 0
                   THEN 'no conditions: the rule matched every finding'
               ELSE 'a condition has an unknown field or operator, or no value: the rule never matched'
           END AS reason
    FROM priority_override_rules r
    WHERE COALESCE(r.is_active, TRUE)
      AND (
          r.conditions IS NULL
          OR jsonb_typeof(r.conditions) <> 'array'
          OR jsonb_array_length(r.conditions) = 0
          OR EXISTS (
              SELECT 1 FROM jsonb_array_elements(r.conditions) c
              WHERE jsonb_typeof(c) <> 'object'
                 OR COALESCE(c->>'field', '') NOT IN ('is_in_kev', 'is_reachable', 'asset_is_crown_jewel',
                                                      'epss_score', 'severity', 'asset_criticality', 'asset_exposure')
                 OR COALESCE(c->>'operator', '') NOT IN ('eq', 'neq', 'gte', 'lte', 'in')
                 OR c->'value' IS NULL
                 OR jsonb_typeof(c->'value') = 'null'
          )
      )
)
INSERT INTO priority_rule_safety_report (rule_id, tenant_id, rule_name, priority_class, reason, conditions)
SELECT id, tenant_id, name, priority_class, reason, conditions FROM invalid
ON CONFLICT (rule_id) DO NOTHING;

UPDATE priority_override_rules r
   SET is_active = FALSE, updated_at = NOW()
  FROM priority_rule_safety_report rep
 WHERE rep.rule_id = r.id
   AND COALESCE(r.is_active, TRUE);

DO $$
DECLARE n INTEGER;
BEGIN
    SELECT count(*) INTO n FROM priority_rule_safety_report;
    RAISE NOTICE 'priority_rule_safety_report: % priority override rule(s) switched off (B17)', n;
END $$;
