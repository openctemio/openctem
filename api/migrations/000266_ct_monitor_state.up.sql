-- Certificate-Transparency monitor rotation state (RFC-036 P0, E1).
--
-- The CT sweep used to query the first 50 domain assets of a tenant on every
-- run and never the rest. It now keeps one row per (tenant, domain) it watches
-- and picks, each run, the domains never queried or queried longest ago, up to
-- the per-run cap. A domain whose sources both fail backs off (12 h, 24 h, 48 h
-- … 7 days) instead of taking a slot every run.
--
-- domain is the normalized name queried (a domain asset, a verified domain or
-- a domain scope target); there is no foreign key to any of them because a
-- name can come from several. Rows of a name no longer watched are harmless
-- and go with the tenant.
CREATE TABLE IF NOT EXISTS ct_monitor_state (
    tenant_id            UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain               TEXT        NOT NULL,
    last_checked_at      TIMESTAMPTZ,
    last_success_at      TIMESTAMPTZ,
    last_source          TEXT        NOT NULL DEFAULT '',
    last_error           TEXT        NOT NULL DEFAULT '',
    consecutive_failures INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at      TIMESTAMPTZ,
    subdomains_seen      INTEGER     NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain),
    CONSTRAINT chk_ct_monitor_state_source CHECK (last_source IN ('', 'crt.sh', 'certspotter')),
    CONSTRAINT chk_ct_monitor_state_failures CHECK (consecutive_failures >= 0)
);
