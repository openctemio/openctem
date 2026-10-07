-- API descriptions of a web origin and the operations they declare
-- (docs/rfcs/RFC-056-web-attack-surface.md WS13): OpenAPI 3, Swagger 2,
-- Postman 2.1, HAR 1.2 or a GraphQL introspection result, uploaded for an
-- origin (http_service) asset. The platform compares the declared operations
-- with the endpoints scans observed (drift: shadow, orphan, zombie, new
-- parameters).
--
-- Only the parsed operations (method, path, parameter NAMES, deprecated) and
-- the document's digest are kept: never the document itself, so examples,
-- server URLs and captured values (a HAR's tokens) are not stored.
--
-- Tenant-scoped; visible exactly when the origin asset is. New, empty tables.

CREATE TABLE api_specs (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    origin_asset_id uuid NOT NULL,
    name            character varying(200) NOT NULL,
    format          character varying(16) NOT NULL,
    title           character varying(200),
    spec_version    character varying(64),
    digest          character(64) NOT NULL,
    size_bytes      integer NOT NULL,
    operation_count integer NOT NULL DEFAULT 0,
    truncated       integer NOT NULL DEFAULT 0,
    uploaded_by     uuid,
    created_at      timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT uq_api_specs_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_api_specs_tenant_origin FOREIGN KEY (tenant_id, origin_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_api_specs_format CHECK (format IN ('openapi3', 'swagger2', 'postman', 'har', 'graphql')),
    CONSTRAINT chk_api_specs_size CHECK (size_bytes BETWEEN 0 AND 10485760)
);

CREATE INDEX idx_api_specs_origin ON api_specs (tenant_id, origin_asset_id, created_at DESC);

CREATE TABLE api_spec_operations (
    tenant_id  uuid NOT NULL,
    spec_id    uuid NOT NULL,
    method     character varying(10) NOT NULL,
    path       character varying(2048) NOT NULL,
    match_key  character varying(2100) NOT NULL,
    deprecated boolean NOT NULL DEFAULT false,
    params     jsonb NOT NULL DEFAULT '[]'::jsonb,
    CONSTRAINT pk_api_spec_operations PRIMARY KEY (spec_id, method, path),
    CONSTRAINT fk_api_spec_operations_spec FOREIGN KEY (tenant_id, spec_id)
        REFERENCES api_specs(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_api_spec_operations_params CHECK (jsonb_typeof(params) = 'array' AND octet_length(params::text) <= 32768)
);

CREATE INDEX idx_api_spec_operations_tenant ON api_spec_operations (tenant_id, spec_id);

COMMENT ON TABLE api_specs IS 'API descriptions of an origin asset; the document itself is never stored, only its digest and parsed operations (RFC-056).';
COMMENT ON TABLE api_spec_operations IS 'Operations an API description declares: method, path, parameter names, deprecated (RFC-056).';

CREATE POLICY api_specs_tenant_isolation ON api_specs
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
CREATE POLICY api_spec_operations_tenant_isolation ON api_spec_operations
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
