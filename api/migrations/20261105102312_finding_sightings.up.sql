-- Finding sightings: who reported a finding, per source, with first and last
-- seen (docs/architecture/decisions/004-finding-provenance.md,
-- docs/architecture/finding-sightings.md).
--
-- One finding, many sightings. A source is the channel (a scan run, a sensor
-- task outside a run, an unsolicited sensor report, an upload, a CI run, a
-- connector, the platform), the tenant's sensor, the sender (a CI
-- repository or connector source name), the tool and the scan definition.
-- A row is kept per finding and source, not per report: a repeat of the
-- same source moves last_seen_at, the last receipt, run, step and command,
-- and counts the receipts that saw it. At most 64 sources per finding (the
-- writer enforces it), so a sensor that varies its tool name cannot grow
-- the table without bound. Rows live as long as their finding.
--
-- The unique key is NULLS NOT DISTINCT: a source with no sensor or no scan
-- is one row, never a duplicate per report.
--
-- Live impact: one new table, its key built with it (empty table). The
-- backfill below reads finding_ingest_actions (90 days), the receipts and
-- the findings once, tenant-pinned joins only; rows it writes have
-- backfilled = true. The secondary indexes are built CONCURRENTLY by the
-- migrations that follow.

CREATE TABLE IF NOT EXISTS finding_sightings (
    tenant_id        uuid         NOT NULL,
    finding_id       uuid         NOT NULL,
    channel          varchar(16)  NOT NULL,
    sensor_id        uuid,
    sender           varchar(128) NOT NULL DEFAULT '',
    tool             varchar(100) NOT NULL DEFAULT '',
    scan_id          uuid,
    tool_version     varchar(100),
    first_seen_at    timestamptz  NOT NULL,
    last_seen_at     timestamptz  NOT NULL,
    seen_count       integer      NOT NULL DEFAULT 1,
    first_receipt_id uuid,
    last_receipt_id  uuid,
    last_source_ref  varchar(128),
    last_run_id      uuid,
    last_step_run_id uuid,
    last_command_id  uuid,
    backfilled       boolean      NOT NULL DEFAULT false,
    CONSTRAINT ux_finding_sightings_source UNIQUE NULLS NOT DISTINCT
        (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id),
    CONSTRAINT fk_finding_sightings_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_sightings_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_sightings_channel
        CHECK (channel IN ('scan', 'task', 'sensor', 'upload', 'ci', 'connector', 'platform', 'unknown')),
    CONSTRAINT chk_finding_sightings_unknown CHECK (channel <> 'unknown' OR backfilled),
    CONSTRAINT chk_finding_sightings_seen CHECK (seen_count >= 1 AND last_seen_at >= first_seen_at)
);

COMMENT ON TABLE finding_sightings IS
    'Who reported a finding: one row per finding and source (channel, the tenant''s sensor, sender, tool, scan definition) with first and last seen, the number of receipts that saw it and the last receipt, run, step and command. At most 64 sources per finding; rows live with their finding.';
COMMENT ON COLUMN finding_sightings.channel IS
    'scan (a sensor in a scan run), task (a sensor command outside a run), sensor (an unsolicited sensor report), upload, ci, connector, platform; unknown only on backfilled rows whose channel could not be derived.';
COMMENT ON COLUMN finding_sightings.sensor_id IS
    'The tenant''s own sensor that reported it; NULL for a shared platform sensor (never exposed to the tenant) and for non-sensor channels. No FK: the sighting outlives a deleted sensor.';
COMMENT ON COLUMN finding_sightings.sender IS
    'The CI repository or connector source name for those channels; empty otherwise. Untrusted text, clipped.';
COMMENT ON COLUMN finding_sightings.seen_count IS
    'Receipts (runs, uploads, reports) that reported the finding from this source; repeats within one receipt count once.';
COMMENT ON COLUMN finding_sightings.backfilled IS
    'true when the row was derived from data written before sightings were recorded (the receipt log, findings.scan_id/sensor_id/last_seen_tool); its first_seen_at is the best known value.';

-- Row-level security in shadow mode, like the other tenant tables.
DROP POLICY IF EXISTS finding_sightings_tenant_isolation ON finding_sightings;
CREATE POLICY finding_sightings_tenant_isolation ON finding_sightings
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));

-- Backfill 1: the receipt action log (kept 90 days). A receipt with one
-- tool row names its tool and sender; otherwise the receipt's tool and no
-- sender. A sensor id is kept only when the sensor is the tenant's own.
INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id,
    first_seen_at, last_seen_at, seen_count, first_receipt_id, last_receipt_id, last_source_ref, last_run_id,
    backfilled)
SELECT a.tenant_id, a.finding_id, a.channel, a.sensor_id, a.sender, a.tool, a.scan_id,
    min(a.created_at), max(a.created_at), count(DISTINCT a.receipt_id)::integer,
    (array_agg(a.receipt_id ORDER BY a.created_at))[1],
    (array_agg(a.receipt_id ORDER BY a.created_at DESC))[1],
    (array_agg(a.source_ref ORDER BY a.created_at DESC))[1],
    (array_agg(a.run_id ORDER BY a.created_at DESC))[1],
    true
FROM (
    SELECT fia.tenant_id, fia.finding_id, fia.receipt_id, fia.created_at, left(r.source_ref, 128) AS source_ref,
        CASE r.source_kind WHEN 'scan_run' THEN 'scan' WHEN 'command' THEN 'task' WHEN 'ci_run' THEN 'ci'
            ELSE r.source_kind END AS channel,
        CASE WHEN rt.instance_kind = 'sensor' THEN s.id END AS sensor_id,
        CASE WHEN rt.instance_kind IN ('ci', 'connector') THEN left(rt.instance_id, 128) ELSE '' END AS sender,
        left(COALESCE(NULLIF(rt.tool, 'unknown'), r.tool_name, ''), 100) AS tool,
        sr.scan_id, sr.id AS run_id
    FROM finding_ingest_actions fia
    JOIN ingest_receipts r ON r.tenant_id = fia.tenant_id AND r.id = fia.receipt_id
    LEFT JOIN LATERAL (
        SELECT min(t.tool) AS tool, min(t.instance_kind) AS instance_kind, min(t.instance_id) AS instance_id
        FROM ingest_receipt_tools t
        WHERE t.tenant_id = r.tenant_id AND t.receipt_id = r.id
        HAVING count(*) = 1
    ) rt ON true
    LEFT JOIN sensors s ON s.tenant_id = fia.tenant_id AND s.id::text = rt.instance_id
    LEFT JOIN scan_runs sr ON r.source_kind = 'scan_run' AND sr.tenant_id = fia.tenant_id AND sr.id::text = r.source_ref
    WHERE fia.action <> 'closed'
) a
GROUP BY a.tenant_id, a.finding_id, a.channel, a.sensor_id, a.sender, a.tool, a.scan_id
ON CONFLICT DO NOTHING;

-- Backfill 2: findings the receipt log does not name, from what the finding
-- row itself kept: an upload receipt id in scan_id, the platform's
-- version-match tool, a sensor, a CI commit, an integration. Anything else
-- is channel unknown (with its tool, so the tool filter still finds it).
INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id,
    first_seen_at, last_seen_at, seen_count, first_receipt_id, last_receipt_id, last_source_ref, backfilled)
SELECT f.tenant_id, f.id,
    CASE
        WHEN up.id IS NOT NULL THEN 'upload'
        WHEN f.tool_name = 'version-match' THEN 'platform'
        WHEN f.sensor_id IS NOT NULL AND f.ingest_channel IN ('scanner', 'collector') THEN 'sensor'
        WHEN f.last_seen_commit IS NOT NULL THEN 'ci'
        WHEN f.ingest_channel = 'integration' THEN 'connector'
        ELSE 'unknown'
    END,
    s.id, '', left(COALESCE(NULLIF(f.last_seen_tool, ''), f.tool_name, ''), 100), NULL,
    LEAST(COALESCE(f.first_detected_at, f.created_at), GREATEST(COALESCE(f.last_seen_at, f.created_at), COALESCE(f.first_detected_at, f.created_at))),
    GREATEST(COALESCE(f.last_seen_at, f.created_at), COALESCE(f.first_detected_at, f.created_at)),
    1, up.id, up.id, up.id::text, true
FROM findings f
LEFT JOIN ingest_receipts up ON up.tenant_id = f.tenant_id AND up.source_kind = 'upload' AND up.id::text = f.scan_id
LEFT JOIN sensors s ON s.tenant_id = f.tenant_id AND s.id = f.sensor_id
WHERE COALESCE(f.ingest_channel::text, '') <> 'manual'
  AND f.source <> 'pentest'
  AND NOT EXISTS (SELECT 1 FROM finding_sightings x WHERE x.tenant_id = f.tenant_id AND x.finding_id = f.id)
ON CONFLICT DO NOTHING;
