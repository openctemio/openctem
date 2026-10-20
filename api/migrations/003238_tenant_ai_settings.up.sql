-- Organization AI settings move out of tenants.settings.ai (JSON) into their
-- own table (docs/architecture/ai-triage.md): the organization's consent, the
-- source (platform AI, its own provider, off), the own provider's kind, base
-- URL and model, its ENCRYPTED key, and the auto-triage policy. A table makes
-- the key easy to rekey and impossible to leak through a settings read.
--
-- Backfill: each organization with a settings.ai object gets one row.
--   mode platform (or none)  -> source 'platform'
--   mode disabled            -> source 'off'
--   mode byok                -> source 'own' when the provider is one of the
--                               four supported kinds, otherwise 'off'
--   mode agent / anything else -> 'off' (never a silent fall back to the platform key)
-- The encrypted key keeps its ciphertext (the "enc:v1:" prefix is removed);
-- a key that was stored without encryption is dropped, and the own provider
-- is turned off until an administrator enters it again. The auto-triage
-- policy keeps only the keys the organization set explicitly, so the
-- platform defaults still apply to the others. Then settings.ai is removed.
--
-- Live impact: one pass over tenants with an ai object; one INSERT per
-- such organization and one UPDATE of tenants.settings. Run twice, it
-- changes nothing the second time (ON CONFLICT DO NOTHING; the ai key is gone).

CREATE TABLE tenant_ai_settings (
    tenant_id      UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    source         TEXT NOT NULL DEFAULT 'platform' CHECK (source IN ('platform', 'own', 'off')),
    provider       TEXT NOT NULL DEFAULT '' CHECK (provider IN ('', 'claude', 'openai', 'gemini', 'openai_compatible')),
    base_url       TEXT NOT NULL DEFAULT '' CHECK (length(base_url) <= 512),
    model          TEXT NOT NULL DEFAULT '' CHECK (length(model) <= 128),
    key_enc        TEXT CHECK (key_enc IS NULL OR length(key_enc) BETWEEN 1 AND 4096),
    key_last4      TEXT NOT NULL DEFAULT '' CHECK (length(key_last4) <= 4),
    key_updated_at TIMESTAMPTZ,
    key_updated_by UUID,
    enabled_at     TIMESTAMPTZ,
    enabled_by     TEXT NOT NULL DEFAULT '' CHECK (length(enabled_by) <= 64),
    policy         JSONB NOT NULL DEFAULT '{}' CHECK (length(policy::text) <= 2048),
    updated_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenant_ai_settings IS 'Per-organization AI triage settings: consent, source, own provider and its encrypted key (APP_ENCRYPTION_KEY, in the rekey registry), auto-triage policy.';
COMMENT ON COLUMN tenant_ai_settings.key_enc IS 'AES-GCM ciphertext (base64) of the own provider API key; write-only, never returned by the API.';

INSERT INTO tenant_ai_settings (tenant_id, source, provider, base_url, model, key_enc, enabled_at, enabled_by, policy)
SELECT t.id,
       CASE
           WHEN COALESCE(a->>'mode', 'platform') = 'platform' THEN 'platform'
           WHEN a->>'mode' = 'byok'
                AND a->>'provider' IN ('claude', 'openai', 'gemini')
                AND COALESCE(a->>'api_key', '') LIKE 'enc:v1:_%' THEN 'own'
           ELSE 'off'
       END,
       CASE WHEN a->>'mode' = 'byok' AND a->>'provider' IN ('claude', 'openai', 'gemini') THEN a->>'provider' ELSE '' END,
       '',
       CASE WHEN a->>'mode' = 'byok' AND a->>'provider' IN ('claude', 'openai', 'gemini')
            THEN left(COALESCE(a->>'model_override', ''), 128) ELSE '' END,
       CASE WHEN a->>'mode' = 'byok' AND a->>'provider' IN ('claude', 'openai', 'gemini')
                 AND COALESCE(a->>'api_key', '') LIKE 'enc:v1:_%'
            THEN substr(a->>'api_key', 8) END,
       CASE WHEN COALESCE(a->>'enabled_at', '') ~ '^\d{4}-\d{2}-\d{2}T' THEN (a->>'enabled_at')::timestamptz END,
       left(COALESCE(a->>'enabled_by', ''), 64),
       jsonb_strip_nulls(jsonb_build_object(
           'auto_triage_enabled', CASE WHEN jsonb_typeof(a->'auto_triage_enabled') = 'boolean' THEN a->'auto_triage_enabled' END,
           'auto_triage_severities', CASE WHEN jsonb_typeof(a->'auto_triage_severities') = 'array' THEN a->'auto_triage_severities' END,
           'auto_triage_delay_seconds', CASE WHEN jsonb_typeof(a->'auto_triage_delay_seconds') = 'number' THEN a->'auto_triage_delay_seconds' END))
  FROM tenants t
 CROSS JOIN LATERAL (SELECT t.settings->'ai' AS a) x
 WHERE jsonb_typeof(x.a) = 'object'
ON CONFLICT (tenant_id) DO NOTHING;

UPDATE tenants SET settings = settings - 'ai' WHERE settings ? 'ai';
