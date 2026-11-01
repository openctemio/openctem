-- What each tool contributed to a receipt (docs/rfcs/RFC-122-ingest-receipts.md).
-- A scan run, a CI run or a connector sync can carry reports of several tools
-- on one receipt; the receipt's tool_name is only the first tool that reported,
-- so the dashboards' intake and the receipt list's tool filter read these rows
-- instead: every report adds its counts to the row of its own tool. The rows of
-- one receipt sum to the receipt's counts.
--
-- 'platform' is the source kind of findings the platform derives itself (the
-- inventory version matcher), recorded on their own receipt instead of on no
-- receipt at all.

CREATE TABLE IF NOT EXISTS ingest_receipt_tools (
    tenant_id      uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    receipt_id     uuid         NOT NULL REFERENCES ingest_receipts(id) ON DELETE CASCADE,
    tool           varchar(100) NOT NULL,
    instance_kind  varchar(16)  NOT NULL DEFAULT '',
    instance_id    varchar(128) NOT NULL DEFAULT '',
    instance_name  varchar(255) NOT NULL DEFAULT '',
    reports        integer      NOT NULL DEFAULT 0,
    received       integer      NOT NULL DEFAULT 0,
    created        integer      NOT NULL DEFAULT 0,
    still_detected integer      NOT NULL DEFAULT 0,
    reopened       integer      NOT NULL DEFAULT 0,
    closed         integer      NOT NULL DEFAULT 0,
    skipped        integer      NOT NULL DEFAULT 0,
    failed         integer      NOT NULL DEFAULT 0,
    suppressed     integer      NOT NULL DEFAULT 0,
    assets_created integer      NOT NULL DEFAULT 0,
    assets_updated integer      NOT NULL DEFAULT 0,
    first_at       timestamptz  NOT NULL DEFAULT now(),
    last_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ingest_receipt_tools PRIMARY KEY (receipt_id, tool, instance_kind, instance_id),
    CONSTRAINT chk_ingest_receipt_tools_instance_kind
        CHECK (instance_kind IN ('', 'sensor', 'ci', 'connector', 'platform', 'import')),
    CONSTRAINT chk_ingest_receipt_tools_counts CHECK (reports >= 0 AND received >= 0 AND created >= 0
        AND still_detected >= 0 AND reopened >= 0 AND closed >= 0 AND skipped >= 0 AND failed >= 0
        AND suppressed >= 0 AND assets_created >= 0 AND assets_updated >= 0)
);

CREATE INDEX IF NOT EXISTS idx_ingest_receipt_tools_tenant_tool
    ON ingest_receipt_tools (tenant_id, tool, receipt_id);

COMMENT ON TABLE ingest_receipt_tools IS
    'Per-tool, per-sender counts of a receipt: what each tool''s reports on that receipt received and did, and who sent them. The dashboards'' intake and the receipt list''s tool filter read these rows, so a source is the tool that reported, not the first tool of a multi-tool run.';
COMMENT ON COLUMN ingest_receipt_tools.instance_id IS
    'The sender of the reports: a sensor id, a CI repository, a connector source name, platform or import; empty for rows written before senders were recorded.';

-- Receipts written before this table: their counts stay on their first tool
-- (the only attribution they recorded) and name no sender.
INSERT INTO ingest_receipt_tools (tenant_id, receipt_id, tool, instance_kind, instance_id, instance_name, reports,
    received, created, still_detected, reopened, closed, skipped, failed, suppressed, assets_created, assets_updated,
    first_at, last_at)
SELECT r.tenant_id, r.id, COALESCE(NULLIF(r.tool_name, ''), 'unknown'),
    CASE r.source_kind WHEN 'upload' THEN 'import' WHEN 'ci_run' THEN CASE WHEN c.id IS NULL THEN '' ELSE 'ci' END ELSE '' END,
    CASE r.source_kind WHEN 'upload' THEN 'import' WHEN 'ci_run' THEN COALESCE(left(c.repository, 128), '') ELSE '' END,
    CASE r.source_kind WHEN 'ci_run' THEN COALESCE(left(c.repository, 255), '') ELSE '' END,
    r.reports, r.findings_received, r.findings_created, r.findings_updated, r.findings_reopened, r.findings_closed,
    r.skipped, r.findings_failed, r.findings_suppressed, r.assets_created, r.assets_updated, r.created_at, r.updated_at
FROM ingest_receipts r
LEFT JOIN ci_runs c ON r.source_kind = 'ci_run' AND c.tenant_id = r.tenant_id AND c.id::text = r.source_ref
ON CONFLICT DO NOTHING;

ALTER TABLE ingest_receipts DROP CONSTRAINT IF EXISTS chk_ingest_receipts_source_kind;
ALTER TABLE ingest_receipts ADD CONSTRAINT chk_ingest_receipts_source_kind
    CHECK (source_kind IN ('upload', 'scan_run', 'command', 'ci_run', 'connector', 'sensor', 'platform'));

ALTER TABLE dash_ingest_day DROP CONSTRAINT IF EXISTS chk_dash_ingest_day_kind;
ALTER TABLE dash_ingest_day ADD CONSTRAINT chk_dash_ingest_day_kind
    CHECK (source_kind IN ('sensor', 'import', 'connector', 'ci', 'platform'));
