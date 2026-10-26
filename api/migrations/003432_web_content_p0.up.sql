-- Web content intelligence, first slice (docs/rfcs/RFC-056-web-attack-surface.md
-- §4.9 and docs/architecture/web-content-pipeline.md).
--
-- 1. Verification planner: a managed scan owner "web_verify" and a ledger of
--    what was already planned for an endpoint, so a sensitive-path hit is
--    verified once per response change and the tenant's daily budget can be
--    counted.
-- 2. Web alerts: the fingerprints of the web change alerts sent, with an
--    expiry, so a flapping endpoint alerts once per fingerprint lifetime.
--
-- Two new, empty tables and a wider CHECK on scans.managed_by.

ALTER TABLE scans DROP CONSTRAINT scans_managed_by_check;
ALTER TABLE scans
    ADD CONSTRAINT scans_managed_by_check CHECK (
        (managed_by IS NULL AND managed_key IS NULL)
        OR (managed_by IN ('coverage', 'enrichment', 'web_verify') AND managed_key IS NOT NULL AND managed_key <> '')
    );

-- One row per endpoint: the response signature the last verification was
-- planned for. A planned verification is never repeated for the same
-- signature (delta gating).
CREATE TABLE web_endpoint_verifications (
    tenant_id    uuid NOT NULL,
    endpoint_id  uuid NOT NULL,
    response_sig character varying(64) NOT NULL,
    catalog_key  character varying(64) NOT NULL,
    planned_at   timestamp with time zone NOT NULL DEFAULT now(),
    run_id       uuid,
    PRIMARY KEY (tenant_id, endpoint_id),
    CONSTRAINT fk_web_endpoint_verifications_endpoint FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES web_endpoints(tenant_id, id) ON DELETE CASCADE
);

-- The daily budget counts a tenant's rows planned in the last day.
CREATE INDEX idx_web_endpoint_verifications_planned ON web_endpoint_verifications (tenant_id, planned_at DESC);

COMMENT ON TABLE web_endpoint_verifications IS 'Verification jobs planned for catalog-matched web endpoints; one row per endpoint, tenant-scoped (RFC-056).';

CREATE POLICY web_endpoint_verifications_tenant_isolation ON web_endpoint_verifications
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

-- Fingerprints of web change alerts already sent: (tenant, origin, kind,
-- template) hashed. An entry older than the tenant's alert fingerprint
-- lifetime no longer suppresses a new alert.
CREATE TABLE web_alert_fingerprints (
    tenant_id       uuid NOT NULL,
    fingerprint     character varying(64) NOT NULL,
    last_alerted_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, fingerprint)
);

CREATE INDEX idx_web_alert_fingerprints_alerted ON web_alert_fingerprints (last_alerted_at);

COMMENT ON TABLE web_alert_fingerprints IS 'Web change alerts already sent, for suppression and expiry; tenant-scoped (RFC-056).';

CREATE POLICY web_alert_fingerprints_tenant_isolation ON web_alert_fingerprints
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
