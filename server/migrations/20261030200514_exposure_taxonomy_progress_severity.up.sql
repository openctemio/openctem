-- Exposure taxonomy, in-progress state and analyst severity override
-- (docs/architecture/exposure-taxonomy.md).
--
-- 1. Three event types: web_interface_exposed, mcp_server_exposed and
--    mail_server_blocklisted.
-- 2. The in_progress state (someone is working on the exposure; still open),
--    on exposure_events and its state history.
-- 3. The analyst severity override. exposure_events.severity stays the
--    EFFECTIVE severity, so every reader is unchanged. Next to it:
--      source_severity           what the producer reported while an override
--                                stands (NULL = no override)
--      severity_override_reason  why the analyst set the severity
--      severity_overridden_by    who (users; SET NULL when the account is erased)
--      severity_overridden_at    when; NULL = no override stands
--    Re-sightings write source_severity while an override stands instead of
--    reverting the analyst. peak_severity (the four-eyes rule) keeps following
--    the reported severity only.
--
-- Live impact: four nullable columns without a default (catalog change, no
-- rewrite). CHECK and FOREIGN KEY constraints are added NOT VALID and then
-- validated, so writes keep going during the scan.

ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_type;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (event_type IN (
    'port_open', 'port_closed', 'service_detected', 'service_changed', 'subdomain_discovered', 'subdomain_removed',
    'certificate_expiring', 'certificate_expired', 'bucket_public', 'bucket_private', 'repo_public', 'repo_private',
    'api_exposed', 'api_removed', 'credential_leaked', 'sensitive_data_exposed', 'misconfiguration', 'dns_change',
    'ssl_issue', 'header_missing', 'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
    'dangling_cname', 'dangling_ns', 'email_security_weak', 'subdomain_takeover', 'lookalike_domain',
    'web_interface_exposed', 'mcp_server_exposed', 'mail_server_blocklisted', 'custom')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_type;

ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_state;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_state
    CHECK (state IN ('active', 'in_progress', 'resolved', 'accepted', 'false_positive')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_state;

ALTER TABLE exposure_state_history DROP CONSTRAINT chk_exposure_state_history_new;
ALTER TABLE exposure_state_history ADD CONSTRAINT chk_exposure_state_history_new
    CHECK (new_state IN ('active', 'in_progress', 'resolved', 'accepted', 'false_positive')) NOT VALID;
ALTER TABLE exposure_state_history VALIDATE CONSTRAINT chk_exposure_state_history_new;
ALTER TABLE exposure_state_history DROP CONSTRAINT chk_exposure_state_history_prev;
ALTER TABLE exposure_state_history ADD CONSTRAINT chk_exposure_state_history_prev
    CHECK (previous_state IN ('active', 'in_progress', 'resolved', 'accepted', 'false_positive')) NOT VALID;
ALTER TABLE exposure_state_history VALIDATE CONSTRAINT chk_exposure_state_history_prev;

ALTER TABLE exposure_events
    ADD COLUMN IF NOT EXISTS source_severity varchar(20),
    ADD COLUMN IF NOT EXISTS severity_override_reason text,
    ADD COLUMN IF NOT EXISTS severity_overridden_by uuid,
    ADD COLUMN IF NOT EXISTS severity_overridden_at timestamptz;

ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_source_severity;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_source_severity
    CHECK (source_severity IS NULL OR source_severity IN ('critical', 'high', 'medium', 'low', 'info')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_source_severity;

ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_severity_override;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_severity_override
    CHECK (severity_overridden_at IS NULL
           OR (source_severity IS NOT NULL AND severity_override_reason IS NOT NULL
               AND btrim(severity_override_reason) <> '' AND length(severity_override_reason) <= 4000)) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_severity_override;

ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS fk_exposure_events_severity_overridden_by;
ALTER TABLE exposure_events ADD CONSTRAINT fk_exposure_events_severity_overridden_by
    FOREIGN KEY (severity_overridden_by) REFERENCES users (id) ON DELETE SET NULL NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT fk_exposure_events_severity_overridden_by;

COMMENT ON COLUMN exposure_events.source_severity IS
    'Severity the producer reported, kept while an analyst override stands; NULL = no override';
COMMENT ON COLUMN exposure_events.severity_override_reason IS 'Why the analyst set the effective severity';
COMMENT ON COLUMN exposure_events.severity_overridden_by IS 'Who set the analyst severity override';
COMMENT ON COLUMN exposure_events.severity_overridden_at IS 'When the analyst severity override was set; NULL = no override';
