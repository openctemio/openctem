-- Reversible masking of AI context (docs/architecture/ai-context-masking.md).
--
-- ai_mask_maps holds, per AI run, the encrypted masking key and the
-- encrypted placeholder -> value map the platform needs to turn the model's
-- output back into real values. Secrets are never in the map. Rows expire
-- (AI_MASK_MAP_TTL, default 7 days) and are purged by the retention job;
-- they go with the organization (ON DELETE CASCADE). run_id has no foreign
-- key: the run table ships separately and a map may outlive nothing else.
--
-- tenant_ai_settings.masking is the organization's masking policy for
-- internal data ('{}' = the platform default: every class masked).
--
-- Live impact: one new empty table; one column with a constant default on
-- tenant_ai_settings (no rewrite on PostgreSQL 11+).

CREATE TABLE ai_mask_maps (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id     uuid NOT NULL,
    key_enc    text NOT NULL CHECK (length(key_enc) BETWEEN 1 AND 1024),
    map_enc    text NOT NULL CHECK (length(map_enc) BETWEEN 1 AND 4194304),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT uq_ai_mask_maps_run UNIQUE (tenant_id, run_id),
    CONSTRAINT chk_ai_mask_maps_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_ai_mask_maps_expires ON ai_mask_maps (expires_at);

COMMENT ON TABLE ai_mask_maps IS 'Per AI run: the masking key and the placeholder-to-value map, both AES-GCM encrypted with APP_ENCRYPTION_KEY (rekey registry); never sent to a model or a worker; expires and is purged.';
COMMENT ON COLUMN ai_mask_maps.key_enc IS 'Encrypted 32-byte per-run masking key (base64 ciphertext).';
COMMENT ON COLUMN ai_mask_maps.map_enc IS 'Encrypted JSON of the reversible placeholders and their values; secrets are never stored.';

CREATE POLICY ai_mask_maps_tenant_isolation ON ai_mask_maps
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

ALTER TABLE tenant_ai_settings
    ADD COLUMN masking jsonb NOT NULL DEFAULT '{}' CHECK (length(masking::text) <= 32768);

COMMENT ON COLUMN tenant_ai_settings.masking IS 'Masking policy for internal AI data: classes turned off, subdomain label switch, extra terms; {} = every class masked. Restricted data and secrets are always masked.';
