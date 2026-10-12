-- Web surface change feed (docs/rfcs/RFC-056-web-attack-surface.md §4.8):
-- one row per change of an endpoint, written in the same transaction as the
-- change: appeared, returned (seen again after it was gone), gone,
-- status_changed, auth_changed, param_added.
--
-- Tenant-scoped; an event is visible exactly when its origin asset is. The
-- composite foreign key ties an event to an endpoint of the same tenant and
-- removes it with the endpoint. detail holds status codes and auth states
-- only, never a value from the target. Kept 90 days (retention controller).
--
-- A new, empty table.

CREATE TABLE web_endpoint_events (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       uuid NOT NULL,
    endpoint_id     uuid NOT NULL,
    origin_asset_id uuid NOT NULL,
    kind            character varying(16) NOT NULL,
    at              timestamp with time zone NOT NULL DEFAULT now(),
    run_id          uuid,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT fk_web_endpoint_events_endpoint FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES web_endpoints(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_endpoint_events_kind CHECK (kind IN ('appeared', 'returned', 'gone', 'status_changed', 'auth_changed', 'param_added')),
    CONSTRAINT chk_web_endpoint_events_detail CHECK (octet_length(detail::text) <= 512)
);

CREATE INDEX idx_web_endpoint_events_tenant_at ON web_endpoint_events (tenant_id, at DESC);
CREATE INDEX idx_web_endpoint_events_origin ON web_endpoint_events (tenant_id, origin_asset_id, at DESC);
CREATE INDEX idx_web_endpoint_events_endpoint ON web_endpoint_events (tenant_id, endpoint_id);

-- The gone sweep reads active endpoints by last sighting.
CREATE INDEX idx_web_endpoints_last_seen ON web_endpoints (state, last_seen_at);

COMMENT ON TABLE web_endpoint_events IS 'Changes of web endpoints (appeared, returned, gone, status/auth changed, parameter added); tenant-scoped, 90 days (RFC-056).';

CREATE POLICY web_endpoint_events_tenant_isolation ON web_endpoint_events
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
