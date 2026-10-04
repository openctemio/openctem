-- EASM DNS-only checks (RFC-036 P1): dangling DNS and email posture.
--
-- 1. Three exposure types for what the checks find:
--    dangling_cname       a CNAME whose target does not exist (subdomain
--                         takeover candidate when the target is a provider
--                         that lets anyone claim the name)
--    dangling_ns          a delegation whose name servers do not exist
--    email_security_weak  SPF / DMARC / MTA-STS / TLS-RPT posture gaps
--    Additive: the CHECK is replaced with the same list plus these three.
--
-- 2. easm_dns_check_state: one row per (asset, check) so each daily run picks
--    the names checked longest ago first, up to a per-run cap, and records the
--    last outcome. Rows go with the asset.
ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_type;

ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (
    event_type IN (
        'port_open', 'port_closed', 'service_detected', 'service_changed',
        'subdomain_discovered', 'subdomain_removed', 'certificate_expiring',
        'certificate_expired', 'bucket_public', 'bucket_private',
        'repo_public', 'repo_private', 'api_exposed', 'api_removed',
        'credential_leaked', 'sensitive_data_exposed', 'misconfiguration',
        'dns_change', 'ssl_issue', 'header_missing',
        'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
        'dangling_cname', 'dangling_ns', 'email_security_weak',
        'custom'
    )
);

CREATE TABLE IF NOT EXISTS easm_dns_check_state (
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        UUID        NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    check_kind      TEXT        NOT NULL,
    last_checked_at TIMESTAMPTZ NOT NULL,
    last_outcome    TEXT        NOT NULL DEFAULT '',
    last_error      TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (asset_id, check_kind),
    CONSTRAINT chk_easm_dns_check_kind CHECK (check_kind IN ('dangling', 'email'))
);

CREATE INDEX IF NOT EXISTS idx_easm_dns_check_state_tenant
    ON easm_dns_check_state (tenant_id, check_kind, last_checked_at);
