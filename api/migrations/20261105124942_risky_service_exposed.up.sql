-- Exposure type risky_service_exposed (docs/architecture/service-kinds.md):
-- an internet-facing service whose measured kind is risky (RDP, SMB, a
-- database, an industrial protocol, ...). The list keeps every type the
-- platform knows. NOT VALID + VALIDATE keeps writes going on a large table.
ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_type;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (event_type IN (
    'port_open', 'port_closed', 'service_detected', 'service_changed', 'subdomain_discovered', 'subdomain_removed',
    'certificate_expiring', 'certificate_expired', 'bucket_public', 'bucket_private', 'repo_public', 'repo_private',
    'api_exposed', 'api_removed', 'credential_leaked', 'sensitive_data_exposed', 'misconfiguration', 'dns_change',
    'ssl_issue', 'header_missing', 'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
    'dangling_cname', 'dangling_ns', 'email_security_weak', 'subdomain_takeover', 'lookalike_domain',
    'web_interface_exposed', 'mcp_server_exposed', 'mail_server_blocklisted', 'third_party_script_added',
    'risky_service_exposed', 'custom')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_type;
