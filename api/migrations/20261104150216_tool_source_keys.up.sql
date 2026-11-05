-- Organization keys of the third-party sources scan tools query (subfinder's
-- passive sources, for one): one write-only key per organization and source,
-- delivered to a sensor only for a task of that organization's job.
-- Design: docs/architecture/tool-source-keys.md.
--
-- Live impact: a new, empty table; no lock on existing tables.

CREATE TABLE tool_source_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source       TEXT NOT NULL CHECK (source ~ '^[a-z][a-z0-9_]{0,63}$'),
    key_enc      TEXT NOT NULL CHECK (length(key_enc) BETWEEN 1 AND 4096),
    key_last4    TEXT NOT NULL DEFAULT '' CHECK (length(key_last4) <= 4),
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (tenant_id, source)
);

COMMENT ON TABLE tool_source_keys IS 'Per-organization keys of third-party sources that scan tools query; delivered only to the sensor holding a task of the organization''s job.';
COMMENT ON COLUMN tool_source_keys.key_enc IS 'AES-GCM ciphertext (base64, APP_ENCRYPTION_KEY, in the rekey registry); write-only, never returned by the API.';
