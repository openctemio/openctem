-- Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
-- addresses"): the exit address of each proxy endpoint, recorded only when
-- the platform's own proxy-test echo saw it.
--
-- proxy_echo_observations: the addresses the echo answered for one live
-- proxy_test command (short-lived evidence, removed when the test finishes
-- and pruned after a day). proxy_endpoint_exits: the exit addresses of an
-- endpoint, kept only where the sensor's claim matched an observation.
-- A sensor's report alone never creates a row.
--
-- Live impact: two new empty tables and one unique constraint on
-- proxy_endpoints (a few rows per tenant; the index builds in milliseconds).

ALTER TABLE proxy_endpoints
    ADD CONSTRAINT uq_proxy_endpoints_tenant_pool_id UNIQUE (tenant_id, pool_id, id);

CREATE TABLE proxy_echo_observations (
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    command_id  uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    address     inet NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, command_id, address),
    CONSTRAINT chk_proxy_echo_observations_host CHECK (masklen(address) = CASE WHEN family(address) = 4 THEN 32 ELSE 128 END)
);

CREATE INDEX idx_proxy_echo_observations_observed ON proxy_echo_observations (observed_at);

CREATE TABLE proxy_endpoint_exits (
    tenant_id     uuid NOT NULL,
    pool_id       uuid NOT NULL,
    endpoint_id   uuid NOT NULL,
    address       inet NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, endpoint_id, address),
    CONSTRAINT fk_proxy_endpoint_exits_endpoint FOREIGN KEY (tenant_id, pool_id, endpoint_id)
        REFERENCES proxy_endpoints (tenant_id, pool_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_proxy_endpoint_exits_host CHECK (masklen(address) = CASE WHEN family(address) = 4 THEN 32 ELSE 128 END)
);

CREATE INDEX idx_proxy_endpoint_exits_tenant_seen ON proxy_endpoint_exits (tenant_id, last_seen_at DESC);
CREATE INDEX idx_proxy_endpoint_exits_pool ON proxy_endpoint_exits (tenant_id, pool_id);

COMMENT ON TABLE proxy_echo_observations IS 'Addresses the platform proxy-test echo saw for a live proxy_test command; evidence only, removed when the test finishes.';
COMMENT ON TABLE proxy_endpoint_exits IS 'Exit addresses of proxy endpoints, recorded only when the sensor result matched an address the platform echo saw.';
