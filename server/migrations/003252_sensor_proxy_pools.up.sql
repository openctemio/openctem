-- Sensor proxy pools (RFC-034, amended): an organization's upstream proxies
-- for scan traffic, the endpoint health the platform scores from sensor
-- reports, and which sensors use which pool. Credentials are stored only
-- encrypted (APP_ENCRYPTION_KEY) and are never returned by the API.
--
-- Safe on populated tables: three new tables, additive permission rows, and
-- the admin-only trigger function re-created with two more permissions.

CREATE TABLE proxy_pools (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        varchar(100) NOT NULL,
    description text NOT NULL DEFAULT '',
    enabled     boolean NOT NULL DEFAULT true,
    is_default  boolean NOT NULL DEFAULT false,
    strategy    varchar(16) NOT NULL DEFAULT 'sticky',
    -- Bumped on every change a sensor would see (endpoints, strategy).
    revision    integer NOT NULL DEFAULT 1,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_proxy_pools_tenant_id_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_proxy_pools_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT chk_proxy_pools_name CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    CONSTRAINT chk_proxy_pools_description CHECK (length(description) <= 1000),
    CONSTRAINT chk_proxy_pools_strategy CHECK (strategy IN ('sticky', 'priority')),
    CONSTRAINT chk_proxy_pools_revision CHECK (revision >= 1)
);

-- At most one default pool per organization.
CREATE UNIQUE INDEX uq_proxy_pools_default ON proxy_pools (tenant_id) WHERE is_default;

COMMENT ON TABLE proxy_pools IS 'Organization proxy pools for sensor scan traffic (RFC-034)';

CREATE TABLE proxy_endpoints (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              uuid NOT NULL,
    pool_id                uuid NOT NULL,
    scheme                 varchar(8) NOT NULL,
    host                   varchar(253) NOT NULL,
    port                   integer NOT NULL,
    label                  varchar(64) NOT NULL DEFAULT '',
    -- Position in the pasted list: lower runs first under the priority strategy.
    priority               integer NOT NULL DEFAULT 0,
    enabled                boolean NOT NULL DEFAULT true,
    -- AES-GCM ciphertext of {"username","password"}; NULL: no credentials.
    credentials_encrypted  text,
    credentials_updated_at timestamptz,
    -- Health, computed by the platform from sensor reports.
    state                  varchar(16) NOT NULL DEFAULT 'probation',
    score                  real NOT NULL DEFAULT 0.5,
    success_ewma           real NOT NULL DEFAULT 1,
    consecutive_failures   integer NOT NULL DEFAULT 0,
    probation_ok           integer NOT NULL DEFAULT 0,
    quarantine_count       integer NOT NULL DEFAULT 0,
    ok_total               bigint NOT NULL DEFAULT 0,
    fail_total             bigint NOT NULL DEFAULT 0,
    handshake_ms_p95       integer,
    last_error             varchar(200) NOT NULL DEFAULT '',
    last_ok_at             timestamptz,
    last_failure_at        timestamptz,
    quarantined_until      timestamptz,
    state_changed_at       timestamptz NOT NULL DEFAULT now(),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_proxy_endpoints_pool FOREIGN KEY (tenant_id, pool_id)
        REFERENCES proxy_pools (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_proxy_endpoints_address UNIQUE (pool_id, scheme, host, port),
    CONSTRAINT chk_proxy_endpoints_scheme CHECK (scheme IN ('http', 'https', 'socks5', 'socks5h')),
    CONSTRAINT chk_proxy_endpoints_port CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT chk_proxy_endpoints_host CHECK (length(host) >= 1),
    CONSTRAINT chk_proxy_endpoints_state CHECK (state IN ('healthy', 'probation', 'quarantined')),
    CONSTRAINT chk_proxy_endpoints_score CHECK (score >= 0 AND score <= 1),
    CONSTRAINT chk_proxy_endpoints_credentials CHECK ((credentials_encrypted IS NULL) = (credentials_updated_at IS NULL))
);

CREATE INDEX idx_proxy_endpoints_pool ON proxy_endpoints (tenant_id, pool_id, priority);

-- A sensor's network path when it is not the organization default:
-- 'direct' (no proxy, even with a default pool) or 'pool'. No row: inherit.
CREATE TABLE proxy_sensor_assignments (
    sensor_id  uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    mode       varchar(8) NOT NULL,
    pool_id    uuid,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_proxy_sensor_assignments_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE,
    -- A pool in use cannot be deleted (the API answers PROXY_POOL_IN_USE).
    CONSTRAINT fk_proxy_sensor_assignments_pool FOREIGN KEY (tenant_id, pool_id)
        REFERENCES proxy_pools (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_proxy_sensor_assignments_mode CHECK (mode IN ('direct', 'pool')),
    CONSTRAINT chk_proxy_sensor_assignments_pool CHECK ((mode = 'pool') = (pool_id IS NOT NULL))
);

CREATE INDEX idx_proxy_sensor_assignments_tenant ON proxy_sensor_assignments (tenant_id);
CREATE INDEX idx_proxy_sensor_assignments_pool ON proxy_sensor_assignments (tenant_id, pool_id) WHERE pool_id IS NOT NULL;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at) VALUES
    ('sensors:egress:read', 'sensors', 'View Sensor Proxies', 'View proxy pools, their endpoints and health, and which sensors use them', true, now()),
    ('sensors:egress:write', 'sensors', 'Manage Sensor Proxies', 'Create and change proxy pools and their credentials, and choose the network path of sensors', true, now()),
    ('sensors:egress:delete', 'sensors', 'Delete Sensor Proxies', 'Delete proxy pools', true, now())
ON CONFLICT (id) DO NOTHING;

-- Owner and admin only: a pool decides where every scan's traffic goes.
INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, p.id, now()
FROM (VALUES ('00000000-0000-0000-0000-000000000001'::uuid), ('00000000-0000-0000-0000-000000000002'::uuid)) AS r(id)
CROSS JOIN (VALUES ('sensors:egress:read'), ('sensors:egress:write'), ('sensors:egress:delete')) AS p(id)
WHERE NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = p.id);

CREATE OR REPLACE FUNCTION public.refuse_admin_only_permission_on_custom_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete',
                             'sensors:egress:write', 'sensors:egress:delete',
                             'scans:ci:write',
                             'sensors:pair', 'sensors:approve', 'sensors:grant:narrow',
                             'sensors:grant:widen', 'sensors:revoke')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
