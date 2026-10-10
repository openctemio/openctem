-- Back to freeze windows. Blackout policies a freeze window can represent
-- (no selector or one zone, exactly one weekly slot or one dated window of at
-- most 31 days) are copied back; other policies and every override are lost.

CREATE TABLE scan_freeze_windows (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_zone_id uuid,
    name character varying(100) NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    timezone character varying(64) NOT NULL,
    recurrence character varying(16) NOT NULL,
    starts_at timestamp with time zone,
    ends_at timestamp with time zone,
    days smallint[],
    start_minute smallint,
    end_minute smallint,
    enabled boolean DEFAULT true NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT uq_scan_freeze_windows_tenant_id_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_scan_freeze_windows_zone FOREIGN KEY (tenant_id, scan_zone_id) REFERENCES scan_zones(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_scan_freeze_windows_description CHECK ((length(description) <= 1000)),
    CONSTRAINT chk_scan_freeze_windows_name CHECK (((length(btrim((name)::text)) >= 1) AND (length(btrim((name)::text)) <= 100))),
    CONSTRAINT chk_scan_freeze_windows_recurrence CHECK (((((recurrence)::text = 'once'::text) AND (starts_at IS NOT NULL) AND (ends_at IS NOT NULL) AND (ends_at > starts_at) AND ((ends_at - starts_at) <= '31 days'::interval) AND (days IS NULL) AND (start_minute IS NULL) AND (end_minute IS NULL)) OR (((recurrence)::text = 'weekly'::text) AND (starts_at IS NULL) AND (ends_at IS NULL) AND (days IS NOT NULL) AND ((cardinality(days) >= 1) AND (cardinality(days) <= 7)) AND (days <@ ARRAY[(1)::smallint, (2)::smallint, (3)::smallint, (4)::smallint, (5)::smallint, (6)::smallint, (7)::smallint]) AND ((start_minute >= 0) AND (start_minute <= 1439)) AND ((end_minute >= 0) AND (end_minute <= 1439)))))
);
COMMENT ON TABLE scan_freeze_windows IS 'Times in which active scan work of the tenant (scan_zone_id NULL) or of one zone is not dispatched';
CREATE INDEX idx_scan_freeze_windows_tenant ON scan_freeze_windows USING btree (tenant_id) WHERE enabled;

WITH fit AS (
    SELECT p.*,
           CASE WHEN p.selector = '{}'::jsonb THEN NULL
                ELSE (p.selector->'scan_zone_ids'->>0)::uuid END AS zone_id
    FROM scan_window_policies p
    WHERE p.kind = 'blackout'
      AND (p.selector = '{}'::jsonb
           OR (p.selector - 'scan_zone_ids' = '{}'::jsonb
               AND jsonb_typeof(p.selector->'scan_zone_ids') = 'array'
               AND jsonb_array_length(p.selector->'scan_zone_ids') = 1))
      AND jsonb_array_length(p.slots) + jsonb_array_length(p.one_offs) = 1
)
INSERT INTO scan_freeze_windows (id, tenant_id, scan_zone_id, name, description, timezone, recurrence,
                                 starts_at, ends_at, days, start_minute, end_minute, enabled, created_by,
                                 created_at, updated_at)
SELECT f.id, f.tenant_id, f.zone_id, f.name, f.description, f.timezone,
       CASE WHEN jsonb_array_length(f.slots) = 1 THEN 'weekly' ELSE 'once' END,
       (f.one_offs->0->>'starts_at')::timestamptz,
       (f.one_offs->0->>'ends_at')::timestamptz,
       CASE WHEN jsonb_array_length(f.slots) = 1
            THEN ARRAY(SELECT d::smallint FROM jsonb_array_elements_text(f.slots->0->'days') AS d) END,
       CASE WHEN jsonb_array_length(f.slots) = 1
            THEN (split_part(f.slots->0->>'start', ':', 1)::int * 60 + split_part(f.slots->0->>'start', ':', 2)::int)::smallint END,
       CASE WHEN jsonb_array_length(f.slots) = 1
            THEN (split_part(f.slots->0->>'end', ':', 1)::int * 60 + split_part(f.slots->0->>'end', ':', 2)::int)::smallint END,
       f.enabled, f.created_by, f.created_at, f.updated_at
FROM fit f
WHERE f.zone_id IS NULL
   OR EXISTS (SELECT 1 FROM scan_zones z WHERE z.tenant_id = f.tenant_id AND z.id = f.zone_id);

DROP INDEX IF EXISTS idx_commands_window_policies;
DROP INDEX IF EXISTS idx_commands_window_hold;
ALTER TABLE commands
    DROP COLUMN window_policy_ids,
    DROP COLUMN window_closed_at,
    DROP COLUMN window_hold;

ALTER TABLE commands ADD COLUMN freeze_override boolean DEFAULT false NOT NULL;
ALTER TABLE scan_runs ADD COLUMN freeze_override boolean DEFAULT false NOT NULL;

DROP TABLE scan_window_overrides;
DROP TABLE scan_window_policies;

DELETE FROM role_permissions WHERE permission_id = 'scans:windows:manage';
DELETE FROM permissions WHERE id = 'scans:windows:manage';
