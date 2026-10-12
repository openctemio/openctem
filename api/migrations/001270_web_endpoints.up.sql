-- Web surface sub-inventory (docs/rfcs/RFC-056-web-attack-surface.md).
--
-- An origin (scheme, host, port) is an http_service asset. The endpoints it
-- serves (a method and a path template) and their parameters (a location and
-- a name) live here, under the origin, like the ports of a host live in
-- asset_services: a crawl of one site writes rows here, never one asset per
-- URL.
--
-- Security:
--   * every row carries tenant_id; the composite foreign keys tie an endpoint
--     to an asset of the SAME tenant and a parameter to an endpoint of the
--     same tenant, so no write can attach a row across tenants;
--   * an endpoint inherits the data scope of its origin asset (the list
--     queries join user_accessible_assets on origin_asset_id);
--   * there is no value column anywhere: parameter values, query values,
--     user info and fragments are never stored; example_path has its
--     token-like segments masked before it is written.
--
-- New, empty tables: no lock on existing data, nothing to backfill.
--
-- A crawl now outputs its origin (an http_service asset), not one asset per
-- URL: the platform katana row says so, like the stage catalog
-- (pkg/domain/stage). A one-row update.

CREATE TABLE web_endpoints (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    origin_asset_id uuid NOT NULL,
    method          character varying(10) NOT NULL,
    path_template   character varying(2048) NOT NULL,
    template_hash   character(64) NOT NULL,
    path_hash       character(64) NOT NULL,
    kind            character varying(16) NOT NULL DEFAULT 'page',
    sources         text[] NOT NULL DEFAULT '{}'::text[],
    example_path    character varying(2048),
    last_status     smallint,
    content_type    character varying(100),
    auth_state      character varying(16) NOT NULL DEFAULT 'unknown',
    technologies    text[] NOT NULL DEFAULT '{}'::text[],
    labels          text[] NOT NULL DEFAULT '{}'::text[],
    response_sig    character varying(32),
    state           character varying(10) NOT NULL DEFAULT 'active',
    in_scope        boolean NOT NULL DEFAULT true,
    catalog_key     character varying(64),
    param_count     smallint NOT NULL DEFAULT 0,
    first_seen_at   timestamp with time zone NOT NULL DEFAULT now(),
    last_seen_at    timestamp with time zone NOT NULL DEFAULT now(),
    last_changed_at timestamp with time zone,
    last_run_id     uuid,
    last_sensor_id  uuid,
    last_tool       character varying(64),
    CONSTRAINT uq_web_endpoints_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_web_endpoints_template UNIQUE (tenant_id, origin_asset_id, template_hash),
    CONSTRAINT fk_web_endpoints_tenant_origin FOREIGN KEY (tenant_id, origin_asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_endpoints_method CHECK (method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT','ANY')),
    CONSTRAINT chk_web_endpoints_path CHECK (left(path_template, 1) = '/'),
    CONSTRAINT chk_web_endpoints_kind CHECK (kind IN ('page','api','script','form','graphql','websocket','other')),
    CONSTRAINT chk_web_endpoints_auth CHECK (auth_state IN ('none','required','redirect_login','unknown')),
    CONSTRAINT chk_web_endpoints_state CHECK (state IN ('active','gone','ignored')),
    CONSTRAINT chk_web_endpoints_status CHECK (last_status IS NULL OR (last_status BETWEEN 100 AND 599)),
    CONSTRAINT chk_web_endpoints_param_count CHECK (param_count >= 0)
);

CREATE INDEX idx_web_endpoints_origin ON web_endpoints (tenant_id, origin_asset_id, state);
CREATE INDEX idx_web_endpoints_pattern ON web_endpoints (tenant_id, path_hash);
CREATE INDEX idx_web_endpoints_first_seen ON web_endpoints (tenant_id, first_seen_at DESC);
CREATE INDEX idx_web_endpoints_catalog ON web_endpoints (tenant_id, catalog_key) WHERE catalog_key IS NOT NULL;
CREATE INDEX idx_web_endpoints_labels ON web_endpoints USING gin (labels);

COMMENT ON TABLE web_endpoints IS 'Endpoints (method + path template) a web origin (http_service asset) serves. Tenant-scoped; visible exactly when the origin asset is (RFC-056).';
COMMENT ON COLUMN web_endpoints.template_hash IS 'sha256 hex of method, newline, path template (ctis/weburl PathHash): the dedup key within an origin.';
COMMENT ON COLUMN web_endpoints.path_hash IS 'sha256 hex of the path template alone: the path-pattern key across the origins of ONE tenant; never compared across tenants.';
COMMENT ON COLUMN web_endpoints.example_path IS 'One concrete path, token-like segments masked; never a query.';
COMMENT ON COLUMN web_endpoints.in_scope IS 'false: the endpoint lies under a scope exclusion; kept for visibility, never targeted or alerted on.';
COMMENT ON COLUMN web_endpoints.response_sig IS 'Hash of status, content type and auth state; a change stamps last_changed_at.';
COMMENT ON COLUMN web_endpoints.last_run_id IS 'Step run of the command whose report last saw the endpoint (from the server-side binding).';

CREATE TABLE web_endpoint_params (
    tenant_id     uuid NOT NULL,
    endpoint_id   uuid NOT NULL,
    location      character varying(12) NOT NULL,
    name          character varying(128) NOT NULL,
    type_hint     character varying(16),
    required      boolean NOT NULL DEFAULT false,
    risk_hints    text[] NOT NULL DEFAULT '{}'::text[],
    sensitive     character varying(16),
    sources       text[] NOT NULL DEFAULT '{}'::text[],
    first_seen_at timestamp with time zone NOT NULL DEFAULT now(),
    last_seen_at  timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT pk_web_endpoint_params PRIMARY KEY (endpoint_id, location, name),
    CONSTRAINT fk_web_endpoint_params_tenant_endpoint FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES web_endpoints(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_endpoint_params_location CHECK (location IN ('query','path','header','cookie','form','json','multipart','graphql_arg'))
);

CREATE INDEX idx_web_endpoint_params_tenant ON web_endpoint_params (tenant_id, endpoint_id);

COMMENT ON TABLE web_endpoint_params IS 'Parameter names of a web endpoint (location + name). There is deliberately no value column (RFC-056).';

-- Row-level security policies in shadow mode, like every tenant table: the
-- policy exists, the table does not enable it yet (docs: RLS shadow mode).
CREATE POLICY web_endpoints_tenant_isolation ON web_endpoints
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
CREATE POLICY web_endpoint_params_tenant_isolation ON web_endpoint_params
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

UPDATE tools SET output_types = ARRAY['service/http']
 WHERE tenant_id IS NULL AND name = 'katana' AND output_types = ARRAY['service/discovered_url'];
