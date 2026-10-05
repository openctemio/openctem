-- EASM email-posture check on root-domain seeds and verified domains
-- (research/22 P0-8, bug 22c B3; docs/architecture/easm-dns-checks.md).
--
-- The email check only looked at `domain` assets, and a seed never creates
-- one, so a seed-only tenant was never checked. A seed or verified domain
-- with no domain asset is now checked by name; its per-name state lives
-- here (easm_dns_check_state is keyed by asset). New and empty.
CREATE TABLE IF NOT EXISTS easm_dns_name_state (
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    check_kind      TEXT        NOT NULL,
    last_checked_at TIMESTAMPTZ NOT NULL,
    last_outcome    TEXT        NOT NULL DEFAULT '',
    last_error      TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, name, check_kind),
    CONSTRAINT chk_easm_dns_name_state_kind CHECK (check_kind IN ('email')),
    CONSTRAINT chk_easm_dns_name_state_name CHECK (length(name) BETWEEN 1 AND 253)
);
