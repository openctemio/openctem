-- Back to the audiences the configurations had before. A configuration whose
-- default audience would then collide with another of the same tenant and
-- issuer keeps its new audience.
UPDATE ci_trust_configs c
SET audience = c.legacy_audience, updated_at = now()
WHERE c.legacy_audience IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM ci_trust_configs o
                  WHERE o.tenant_id = c.tenant_id AND o.id <> c.id AND o.issuer = c.issuer AND o.audience = c.legacy_audience);

ALTER TABLE ci_pipelines DROP COLUMN IF EXISTS audience_upgraded_at;
ALTER TABLE ci_trust_configs
    DROP COLUMN IF EXISTS legacy_audience_until,
    DROP COLUMN IF EXISTS legacy_audience;
