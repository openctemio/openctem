-- Signed license of a self-managed installation
-- (docs/rfcs/RFC-145-enterprise-license-and-entitlements.md). Installation-wide
-- state owned by platform administrators: no tenant_id by design, no tenant
-- data. Each stored file is re-verified against the roots compiled into the
-- build whenever it is loaded, so a row written straight into the table grants
-- nothing.

-- Every license ever stored (append-only; removal sets removed_at). The file
-- is the signed license; the other columns are its parsed claims, kept for
-- display and history only.
CREATE TABLE IF NOT EXISTS subscription_licenses (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id     TEXT        NOT NULL,
    customer_id    TEXT        NOT NULL,
    license_type   TEXT        NOT NULL,
    licensee_name  TEXT        NOT NULL,
    issued_at      TIMESTAMPTZ NOT NULL,
    not_before     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    grace_days     INTEGER     NOT NULL,
    entitlements   TEXT[]      NOT NULL DEFAULT '{}',
    keyset_version BIGINT      NOT NULL,
    signing_key_id TEXT        NOT NULL,
    file           BYTEA       NOT NULL,
    source         TEXT        NOT NULL,
    -- The platform account that added or removed it (NULL: the system, a
    -- boot seed or a relay renewal). The admin audit log is the record.
    added_by       UUID,
    added_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_by     UUID,
    removed_at     TIMESTAMPTZ,
    CONSTRAINT chk_subscription_licenses_file CHECK (octet_length(file) BETWEEN 1 AND 65536),
    CONSTRAINT chk_subscription_licenses_source CHECK (source IN ('upload', 'code', 'seed', 'relay')),
    CONSTRAINT chk_subscription_licenses_type CHECK (license_type IN ('enterprise', 'trial', 'non_production')),
    CONSTRAINT chk_subscription_licenses_text CHECK (char_length(license_id) <= 80 AND char_length(customer_id) <= 80
        AND char_length(licensee_name) <= 200 AND char_length(signing_key_id) <= 100),
    CONSTRAINT chk_subscription_licenses_grace CHECK (grace_days BETWEEN 0 AND 90),
    CONSTRAINT chk_subscription_licenses_dates CHECK (expires_at > not_before)
);

COMMENT ON TABLE subscription_licenses IS 'Signed licenses of this installation (append-only history). Installation-wide, no tenant data; re-verified on every load.';

-- One stored (not removed) row per license id.
CREATE UNIQUE INDEX IF NOT EXISTS uq_subscription_licenses_active ON subscription_licenses (license_id) WHERE removed_at IS NULL;

-- The installation's license state: one row. installation_id identifies the
-- installation for bound licenses and usage exports; time_high_water is the
-- highest effective time seen (a clock wound back cannot go below it);
-- keyset_high_water and the revoked lists come from the newest key set seen;
-- version changes on every license write so other replicas reload.
CREATE TABLE IF NOT EXISTS subscription_state (
    singleton           BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    installation_id     UUID        NOT NULL DEFAULT gen_random_uuid(),
    time_high_water     TIMESTAMPTZ NOT NULL DEFAULT now(),
    keyset_high_water   BIGINT      NOT NULL DEFAULT 0,
    revoked_license_ids TEXT[]      NOT NULL DEFAULT '{}',
    revoked_key_ids     TEXT[]      NOT NULL DEFAULT '{}',
    version             BIGINT      NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_subscription_state_singleton CHECK (singleton),
    CONSTRAINT chk_subscription_state_keyset CHECK (keyset_high_water >= 0)
);

COMMENT ON TABLE subscription_state IS 'License state of this installation (one row): installation id, time and key-set high-water marks, revocations, reload version.';

INSERT INTO subscription_state (singleton) VALUES (TRUE) ON CONFLICT (singleton) DO NOTHING;
