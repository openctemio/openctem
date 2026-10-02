-- RFC-026 (docs/rfcs/RFC-026-sensor-results-ingest.md) WP-A4: sensor protocol
-- v2 results. Expand only: one new table, nullable columns on ingest_jobs and
-- new indexes. v1 rows are unaffected (every new ingest_jobs column is NULL
-- for them, and no existing index or constraint changes).

-- One row per v2 report: PUT /api/v2/sensor/results/{report_id}, identified
-- by (tenant, sensor, report_id). Provenance is stamped by the server; nothing
-- here is read from the CTIS body except the segment header (tool + metadata)
-- that every segment must repeat byte-identically.
CREATE TABLE IF NOT EXISTS ingest_reports (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The tenant comes from the sensor key, never from the body; the
    -- composite key makes a report of one tenant's sensor under another
    -- tenant unrepresentable (same rule as RFC-023 Phase 1).
    sensor_id             UUID NOT NULL,
    report_id             UUID NOT NULL,
    command_id            UUID REFERENCES commands(id) ON DELETE SET NULL,
    -- From commands.scan_zone_id, never from the sensor.
    scan_zone_id          UUID REFERENCES scan_zones(id) ON DELETE SET NULL,
    state                 TEXT NOT NULL DEFAULT 'receiving',
    -- Provenance stamped by the server.
    protocol              SMALLINT NOT NULL DEFAULT 2,
    media_type            TEXT NOT NULL,
    sensor_type           TEXT NOT NULL DEFAULT '',
    user_agent            TEXT NOT NULL DEFAULT '',
    -- Segment header: sha-256 of the canonical tool + metadata every segment
    -- must carry, and the header itself for the commit-time steps.
    header_digest         TEXT NOT NULL,
    header                JSONB NOT NULL DEFAULT '{}'::jsonb,
    tool_name             TEXT NOT NULL DEFAULT '',
    -- Single-request PUT: one segment plus an implicit commit.
    implicit_commit       BOOLEAN NOT NULL DEFAULT FALSE,
    segment_count         INT,
    segments_received     INT NOT NULL DEFAULT 0,
    committed_at          TIMESTAMPTZ,
    -- Per-segment outcome, keyed by segment number: counts and item errors.
    -- Written by the worker with an idempotent per-key set, so a segment the
    -- worker retries is never counted twice. Totals are derived on read.
    segment_outcomes      JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Union of the asset ids the processed segments upserted: the scope of
    -- the commit-time auto-resolve.
    touched_asset_ids     UUID[] NOT NULL DEFAULT '{}',
    auto_resolved         INT NOT NULL DEFAULT 0,
    auto_resolve          TEXT,
    -- An uncommitted report expires this long after its last segment.
    expires_at            TIMESTAMPTZ NOT NULL,
    received_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ingest_reports_state_check
        CHECK (state IN ('receiving', 'queued', 'processing', 'completed', 'failed', 'expired')),
    CONSTRAINT ingest_reports_auto_resolve_check
        CHECK (auto_resolve IS NULL OR auto_resolve IN ('applied', 'held', 'skipped')),
    CONSTRAINT ingest_reports_segment_count_check
        CHECK (segment_count IS NULL OR segment_count BETWEEN 1 AND 256),
    CONSTRAINT ingest_reports_segments_check CHECK (segments_received >= 0),
    CONSTRAINT ingest_reports_protocol_check CHECK (protocol = 2),
    CONSTRAINT fk_ingest_reports_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE
);

-- The idempotency key of a report: one report_id per (tenant, sensor).
CREATE UNIQUE INDEX IF NOT EXISTS ux_ingest_reports_tenant_sensor_report
    ON ingest_reports (tenant_id, sensor_id, report_id);

-- Open-report cap per sensor and the expiry sweep.
CREATE INDEX IF NOT EXISTS ix_ingest_reports_open
    ON ingest_reports (sensor_id, expires_at)
    WHERE state = 'receiving';

-- ingest_jobs carries v2 segments (and the commit step) through the RFC-005
-- queue. All columns nullable: v1 rows leave them NULL.
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS protocol SMALLINT;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS ingest_report_id UUID
    REFERENCES ingest_reports(id) ON DELETE CASCADE;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS segment_seq INT;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS content_digest TEXT;
ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS media_type TEXT;

-- v2 idempotency: one job per segment of a report, and one commit job (the
-- row without a segment number).
CREATE UNIQUE INDEX IF NOT EXISTS ux_ingest_jobs_report_segment
    ON ingest_jobs (ingest_report_id, segment_seq)
    WHERE ingest_report_id IS NOT NULL AND segment_seq IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_ingest_jobs_report_commit
    ON ingest_jobs (ingest_report_id)
    WHERE ingest_report_id IS NOT NULL AND segment_seq IS NULL;
