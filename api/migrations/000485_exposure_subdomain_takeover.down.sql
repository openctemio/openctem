-- Rows of the removed type cannot satisfy the restored CHECK.
DELETE FROM exposure_events WHERE event_type = 'subdomain_takeover';

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
