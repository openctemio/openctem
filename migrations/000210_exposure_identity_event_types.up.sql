-- =============================================================================
-- Migration 210: Identity exposure event types
-- =============================================================================
-- Extends the exposure_events.event_type CHECK constraint with the identity
-- attack-surface exposure types emitted by the EntraID/IdP identity-exposure
-- discovery source (docs/rfcs/RFC-018-identity-exposure-discovery.md):
--
--   identity_mfa_gap        — a human/privileged principal without strong MFA
--   identity_stale_principal — an enabled account with no recent sign-in
--   identity_overprivileged  — a principal holding a privileged directory role
--
-- These are exposures (posture weaknesses on directory principals), NOT CVEs,
-- so they belong in the Exposure Register alongside leaked credentials and
-- misconfigurations — the CTEM Discovery "exposure ≠ vulnerability" principle.
--
-- Additive-only: the CHECK is replaced with the same list plus three values.
-- No existing rows are affected.

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
        'custom'
    )
);
