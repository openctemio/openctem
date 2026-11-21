-- finding_web_locations: where on a web origin a finding was observed
-- (CTIS finding.web): the HTTP method, the parameter's location and name,
-- the response status and the stored web endpoint the finding belongs to.
-- One row per finding; a parameter's value is never stored.
CREATE TABLE IF NOT EXISTS finding_web_locations (
    tenant_id      uuid         NOT NULL,
    finding_id     uuid         NOT NULL,
    method         varchar(10),
    param_location varchar(16),
    param_name     varchar(128),
    status_code    smallint,
    endpoint_id    uuid,
    updated_at     timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, finding_id),
    CONSTRAINT fk_finding_web_locations_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_web_locations_endpoint FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES web_endpoints (tenant_id, id) ON DELETE SET NULL (endpoint_id),
    CONSTRAINT chk_finding_web_locations_method CHECK (method IS NULL
        OR method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT')),
    CONSTRAINT chk_finding_web_locations_status CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
    CONSTRAINT chk_finding_web_locations_param CHECK (param_name IS NULL OR char_length(param_name) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_finding_web_locations_endpoint
    ON finding_web_locations (tenant_id, endpoint_id) WHERE endpoint_id IS NOT NULL;

COMMENT ON TABLE finding_web_locations IS
    'The web location of a finding (CTIS finding.web): method, parameter location and name (never a value), response status and the web_endpoints row it belongs to. endpoint_id is set when the report''s endpoint_ref resolves, or when the finding''s method and URL template match an endpoint of the same origin and tenant; NULL otherwise. Rows live with their finding.';

-- The policy only; row-level security is switched on per table by the rollout
-- (docs/architecture/rls-rollout.md), like the sibling finding tables.
DROP POLICY IF EXISTS finding_web_locations_tenant_isolation ON finding_web_locations;
CREATE POLICY finding_web_locations_tenant_isolation ON finding_web_locations
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
