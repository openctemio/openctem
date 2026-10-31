-- Reverse of the exposure taxonomy migration. Exposures of the three new
-- types become custom, in-progress exposures become active again, and a
-- standing override is undone (the reported severity becomes the severity).

UPDATE exposure_events SET severity = source_severity
 WHERE severity_overridden_at IS NOT NULL AND source_severity IS NOT NULL;

ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS fk_exposure_events_severity_overridden_by;
ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_severity_override;
ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_source_severity;
ALTER TABLE exposure_events
    DROP COLUMN IF EXISTS severity_overridden_at,
    DROP COLUMN IF EXISTS severity_overridden_by,
    DROP COLUMN IF EXISTS severity_override_reason,
    DROP COLUMN IF EXISTS source_severity;

UPDATE exposure_state_history SET new_state = 'active' WHERE new_state = 'in_progress';
UPDATE exposure_state_history SET previous_state = 'active' WHERE previous_state = 'in_progress';
ALTER TABLE exposure_state_history DROP CONSTRAINT chk_exposure_state_history_prev;
ALTER TABLE exposure_state_history ADD CONSTRAINT chk_exposure_state_history_prev
    CHECK (previous_state IN ('active', 'resolved', 'accepted', 'false_positive'));
ALTER TABLE exposure_state_history DROP CONSTRAINT chk_exposure_state_history_new;
ALTER TABLE exposure_state_history ADD CONSTRAINT chk_exposure_state_history_new
    CHECK (new_state IN ('active', 'resolved', 'accepted', 'false_positive'));

UPDATE exposure_events SET state = 'active' WHERE state = 'in_progress';
ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_state;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_state
    CHECK (state IN ('active', 'resolved', 'accepted', 'false_positive'));

UPDATE exposure_events SET event_type = 'custom'
 WHERE event_type IN ('web_interface_exposed', 'mcp_server_exposed', 'mail_server_blocklisted');
ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_type;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (event_type IN (
    'port_open', 'port_closed', 'service_detected', 'service_changed', 'subdomain_discovered', 'subdomain_removed',
    'certificate_expiring', 'certificate_expired', 'bucket_public', 'bucket_private', 'repo_public', 'repo_private',
    'api_exposed', 'api_removed', 'credential_leaked', 'sensitive_data_exposed', 'misconfiguration', 'dns_change',
    'ssl_issue', 'header_missing', 'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
    'dangling_cname', 'dangling_ns', 'email_security_weak', 'subdomain_takeover', 'lookalike_domain', 'custom'));
