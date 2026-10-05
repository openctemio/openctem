-- Scan freeze windows (docs/architecture/scan-zones.md, "Freeze windows").
--
-- A freeze window is a time in which no active (T1/T2) scan work of the
-- tenant, or of one scan zone, is dispatched: operators' maintenance windows.
--
--   scan_freeze_windows        the windows: once (start/end instants) or
--                              weekly (ISO days + local start/end minute in
--                              an IANA time zone); a weekly window whose end
--                              is not after its start ends the next day
--   pipeline_runs.freeze_override, commands.freeze_override
--                              set by the server when a member with
--                              scans:freeze:override started the run during
--                              a window; the claim predicate lets such
--                              commands through
--   scans:freeze:override      the permission (owner and admin)
--
-- Live impact: one new table; two NOT NULL DEFAULT false columns (catalog-only
-- on PostgreSQL 11+, no rewrite); one permission row and its role grants.

CREATE TABLE IF NOT EXISTS scan_freeze_windows (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL: the window freezes the whole tenant.
    scan_zone_id UUID,
    name         VARCHAR(100) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    timezone     VARCHAR(64) NOT NULL,
    recurrence   VARCHAR(16) NOT NULL,
    starts_at    TIMESTAMPTZ,
    ends_at      TIMESTAMPTZ,
    days         SMALLINT[],
    start_minute SMALLINT,
    end_minute   SMALLINT,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_scan_freeze_windows_tenant_id_id UNIQUE (tenant_id, id),
    -- Same-tenant zone, and the window goes with its zone.
    CONSTRAINT fk_scan_freeze_windows_zone FOREIGN KEY (tenant_id, scan_zone_id)
        REFERENCES scan_zones (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_scan_freeze_windows_name CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    CONSTRAINT chk_scan_freeze_windows_description CHECK (length(description) <= 1000),
    CONSTRAINT chk_scan_freeze_windows_recurrence CHECK (
        (recurrence = 'once'
            AND starts_at IS NOT NULL AND ends_at IS NOT NULL
            AND ends_at > starts_at AND ends_at - starts_at <= INTERVAL '31 days'
            AND days IS NULL AND start_minute IS NULL AND end_minute IS NULL)
        OR
        (recurrence = 'weekly'
            AND starts_at IS NULL AND ends_at IS NULL
            AND days IS NOT NULL AND cardinality(days) BETWEEN 1 AND 7
            AND days <@ ARRAY[1, 2, 3, 4, 5, 6, 7]::smallint[]
            AND start_minute BETWEEN 0 AND 1439 AND end_minute BETWEEN 0 AND 1439)
    )
);

COMMENT ON TABLE scan_freeze_windows IS
    'Times in which active scan work of the tenant (scan_zone_id NULL) or of one zone is not dispatched';

CREATE INDEX IF NOT EXISTS idx_scan_freeze_windows_tenant
    ON scan_freeze_windows (tenant_id) WHERE enabled;

ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS freeze_override BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS freeze_override BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO permissions (id, module_id, name, description) VALUES
    ('scans:freeze:override', 'scans', 'Override Scan Freeze Windows',
     'Start a scan by hand while a freeze window is active (audited)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'scans:freeze:override'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
WHERE EXISTS (SELECT 1 FROM roles WHERE id = r.role_id)
ON CONFLICT DO NOTHING;
