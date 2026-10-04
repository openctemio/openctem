-- RFC-036 P1: a sensor-confirmed subdomain takeover. The DNS-only check
-- raises dangling_cname (medium, "confirmation: pending"); when a nuclei
-- takeover template run by the tenant's own scan matches the same name, the
-- platform raises subdomain_takeover (high) and marks the dangling_cname
-- confirmed. Additive: the CHECK is replaced with the same list plus one type.
-- Live tables are populated: the constraint is added NOT VALID (brief lock,
-- no scan) and validated in a second step, which only takes a SHARE UPDATE
-- EXCLUSIVE lock; every existing row satisfies it (the old list is a subset).
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
        'subdomain_takeover',
        'custom'
    )
) NOT VALID;

ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_type;
