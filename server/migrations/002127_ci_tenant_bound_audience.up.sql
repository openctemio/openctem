-- CI trust audiences name the tenant for every provider but Azure Pipelines
-- (RFC-051 §3): a token minted for one organization is then useless to any
-- other. GitHub and GitLab configurations whose audience does not contain the
-- tenant id move to the default audience. The old one is kept as
-- legacy_audience for 90 days: a pipeline that existed before may still use
-- it until it exchanges a token with the new audience once
-- (ci_pipelines.audience_upgraded_at); a new pipeline must use the new one.

ALTER TABLE ci_trust_configs
    ADD COLUMN IF NOT EXISTS legacy_audience VARCHAR(500),
    ADD COLUMN IF NOT EXISTS legacy_audience_until TIMESTAMPTZ;

ALTER TABLE ci_pipelines
    ADD COLUMN IF NOT EXISTS audience_upgraded_at TIMESTAMPTZ;

UPDATE ci_trust_configs
SET legacy_audience = audience,
    legacy_audience_until = now() + interval '90 days',
    audience = 'openctem:tenant:' || tenant_id::text,
    updated_at = now()
WHERE provider IN ('github', 'gitlab')
  AND position(tenant_id::text IN audience) = 0;
