-- =============================================================================
-- Migration 210: Identity exposure event types (Down)
-- =============================================================================
-- Reverts the CHECK constraint to the pre-identity list. Any identity_* rows
-- must be removed first or the ADD CONSTRAINT will fail; they are deleted here
-- because they can only have been produced by the identity discovery source.

DELETE FROM exposure_events
WHERE event_type IN ('identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged');

ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_type;

ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (
    event_type IN (
        'port_open', 'port_closed', 'service_detected', 'service_changed',
        'subdomain_discovered', 'subdomain_removed', 'certificate_expiring',
        'certificate_expired', 'bucket_public', 'bucket_private',
        'repo_public', 'repo_private', 'api_exposed', 'api_removed',
        'credential_leaked', 'sensitive_data_exposed', 'misconfiguration',
        'dns_change', 'ssl_issue', 'header_missing', 'custom'
    )
);
