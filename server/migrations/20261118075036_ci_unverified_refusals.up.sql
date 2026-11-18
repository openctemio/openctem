-- ci_unverified_refusals: CI token exchanges refused before the token
-- verified (no trust configuration for its issuer, the issuer's keys
-- unavailable, a token that did not verify). Nothing reaches the tenant's
-- audit log for them (an anonymous caller must not fill it); this bounded,
-- deduplicated record lets the organization's administrators see why their
-- pipeline is refused. One row per (tenant, issuer, reason); no token
-- contents. The API keeps at most 20 rows per tenant and writes a row only
-- for a tenant that has a CI trust configuration.
CREATE TABLE IF NOT EXISTS ci_unverified_refusals (
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The issuer the token claimed: a plain https address of at most 255
    -- characters, else empty.
    issuer     TEXT        NOT NULL DEFAULT '' CHECK (char_length(issuer) <= 255),
    reason     TEXT        NOT NULL CHECK (reason IN ('no_configuration', 'keys_unavailable', 'not_verified')),
    cause      TEXT        NOT NULL DEFAULT '' CHECK (char_length(cause) <= 32),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    count      BIGINT      NOT NULL DEFAULT 1 CHECK (count > 0),
    PRIMARY KEY (tenant_id, issuer, reason)
);

CREATE INDEX IF NOT EXISTS idx_ci_unverified_refusals_tenant_seen
    ON ci_unverified_refusals (tenant_id, last_seen DESC);

COMMENT ON TABLE ci_unverified_refusals IS
    'CI token exchanges refused before verification, per tenant, issuer and reason (bounded, no token contents).';
