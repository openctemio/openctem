-- Scan window policies (RFC-067, docs/architecture/scan-windows.md).
--
-- One model for when scans may touch which targets: allow and blackout
-- policies selected by asset tags, groups, types, criticality, business
-- units, scope entries, zones and programs. Freeze windows become blackout
-- policies and their table, columns and permission go (one-step upgrade):
--   * every scan_freeze_windows row is copied as a blackout policy of tier 1
--     (active and intrusive work), its zone as the selector, its weekly slot
--     or one-off window, grace 15 minutes;
--   * commands.freeze_override and scan_runs.freeze_override are dropped: an
--     override is now a time-boxed state of the organization
--     (scan_window_overrides), not a flag on one run;
--   * scans:windows:manage is granted to owner and admin (migration 001631
--     renames scans:freeze:override to scans:windows:override).
--
-- Safe on populated tables: two new tables, three nullable columns on
-- commands (no rewrite), small partial indexes, a copy of at most 50 rows per
-- organization.

CREATE TABLE scan_window_policies (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           varchar(100) NOT NULL,
    description    text NOT NULL DEFAULT '',
    enabled        boolean NOT NULL DEFAULT true,
    kind           varchar(16) NOT NULL,
    min_tier       smallint NOT NULL DEFAULT 1,
    selector       jsonb NOT NULL DEFAULT '{}'::jsonb,
    timezone       varchar(64) NOT NULL,
    slots          jsonb NOT NULL DEFAULT '[]'::jsonb,
    one_offs       jsonb NOT NULL DEFAULT '[]'::jsonb,
    grace_minutes  smallint NOT NULL DEFAULT 15,
    rate_limit_rps integer NOT NULL DEFAULT 0,
    max_concurrent integer NOT NULL DEFAULT 0,
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_scan_window_policies_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_scan_window_policies_name CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
    CONSTRAINT chk_scan_window_policies_description CHECK (char_length(description) <= 1000),
    CONSTRAINT chk_scan_window_policies_kind CHECK (kind IN ('allow', 'blackout')),
    CONSTRAINT chk_scan_window_policies_tier CHECK (min_tier BETWEEN 0 AND 2),
    CONSTRAINT chk_scan_window_policies_selector CHECK (jsonb_typeof(selector) = 'object'),
    CONSTRAINT chk_scan_window_policies_slots CHECK (jsonb_typeof(slots) = 'array' AND jsonb_array_length(slots) <= 14),
    CONSTRAINT chk_scan_window_policies_one_offs CHECK (jsonb_typeof(one_offs) = 'array' AND jsonb_array_length(one_offs) <= 20),
    CONSTRAINT chk_scan_window_policies_windows CHECK (jsonb_array_length(slots) + jsonb_array_length(one_offs) > 0),
    CONSTRAINT chk_scan_window_policies_grace CHECK (grace_minutes BETWEEN 0 AND 240),
    CONSTRAINT chk_scan_window_policies_caps CHECK (
        rate_limit_rps >= 0 AND max_concurrent >= 0
        AND (kind = 'allow' OR (rate_limit_rps = 0 AND max_concurrent = 0)))
);

CREATE INDEX idx_scan_window_policies_tenant ON scan_window_policies (tenant_id) WHERE enabled;

CREATE TABLE scan_window_overrides (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL: every policy of the organization.
    policy_id  uuid,
    reason     text NOT NULL,
    starts_at  timestamptz NOT NULL,
    ends_at    timestamptz NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_scan_window_overrides_policy FOREIGN KEY (tenant_id, policy_id)
        REFERENCES scan_window_policies (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_scan_window_overrides_reason CHECK (char_length(btrim(reason)) BETWEEN 10 AND 500),
    CONSTRAINT chk_scan_window_overrides_span CHECK (ends_at > starts_at AND ends_at - starts_at <= interval '24 hours')
);

CREATE INDEX idx_scan_window_overrides_tenant ON scan_window_overrides (tenant_id, ends_at) WHERE revoked_at IS NULL;

-- Freeze windows become blackout policies (same ids).
INSERT INTO scan_window_policies (id, tenant_id, name, description, enabled, kind, min_tier, selector,
                                  timezone, slots, one_offs, grace_minutes, created_by, created_at, updated_at)
SELECT fw.id, fw.tenant_id, fw.name, fw.description, fw.enabled, 'blackout', 1,
       CASE WHEN fw.scan_zone_id IS NULL THEN '{}'::jsonb
            ELSE jsonb_build_object('scan_zone_ids', jsonb_build_array(fw.scan_zone_id::text)) END,
       fw.timezone,
       CASE WHEN fw.recurrence = 'weekly' THEN jsonb_build_array(jsonb_build_object(
                'days', to_jsonb(fw.days),
                'start', lpad((fw.start_minute / 60)::text, 2, '0') || ':' || lpad((fw.start_minute % 60)::text, 2, '0'),
                'end', lpad((fw.end_minute / 60)::text, 2, '0') || ':' || lpad((fw.end_minute % 60)::text, 2, '0')))
            ELSE '[]'::jsonb END,
       CASE WHEN fw.recurrence = 'once' THEN jsonb_build_array(jsonb_build_object(
                'starts_at', to_char(fw.starts_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                'ends_at', to_char(fw.ends_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')))
            ELSE '[]'::jsonb END,
       15, fw.created_by, fw.created_at, fw.updated_at
FROM scan_freeze_windows fw;

DROP TABLE scan_freeze_windows;

ALTER TABLE commands DROP COLUMN freeze_override;
ALTER TABLE scan_runs DROP COLUMN freeze_override;

-- Why a pending job waits for a window, when a running job's window closed,
-- and the allow policies a handed-out job runs under (concurrency caps).
ALTER TABLE commands
    ADD COLUMN window_hold jsonb,
    ADD COLUMN window_closed_at timestamptz,
    ADD COLUMN window_policy_ids uuid[];

CREATE INDEX idx_commands_window_hold ON commands (tenant_id) WHERE window_hold IS NOT NULL AND status = 'pending';
CREATE INDEX idx_commands_window_policies ON commands USING gin (window_policy_ids)
    WHERE window_policy_ids IS NOT NULL AND status IN ('acknowledged', 'running');

-- Managing policies: owner and admin.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('scans:windows:manage', 'scans', 'Manage Scan Windows', 'Create, edit and delete scan window policies: when scans may touch which targets', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'scans:windows:manage'
FROM (VALUES ('00000000-0000-0000-0000-000000000001'::uuid), ('00000000-0000-0000-0000-000000000002'::uuid)) AS r(id)
ON CONFLICT (role_id, permission_id) DO NOTHING;
