-- Import and run receipts (docs/rfcs/RFC-122-ingest-receipts.md).
--
-- One receipt per upload and per sensor run (a scan run, a command outside
-- a run, a CI run, a connector sync, an unsolicited sensor report) with what
-- it did to the tenant's findings: created, still detected, reopened,
-- closed, untouched, skipped, failed. finding_ingest_actions links each
-- finding to the receipt with its action (capped per receipt, kept 90 days).
-- dash_ingest_day is the daily ingest-outcome fact the dashboards read,
-- written by the same writer in the same transaction.
--
-- finding_imports (one row per imported file) becomes ingest_receipts: its
-- rows are kept as upload receipts, so findings.scan_id and assets.import_id
-- keep naming their producer.
--
-- Live impact: a rename and new nullable or defaulted columns on
-- finding_imports (small: one row per imported file), a one-pass backfill of
-- source_ref on those rows, two new empty tables. Upgrade note: the API
-- must be replaced together with this migration; an import made by an old
-- API process after it ran fails and can be repeated.

-- expand-contract-ok: finding_imports is written only by the import handler, replaced in the same release; an import during the deploy window fails and is repeated (upgrade note in the changelog)
ALTER TABLE finding_imports RENAME TO ingest_receipts;
-- expand-contract-ok: index and constraint names follow the table rename; no code names them
ALTER INDEX finding_imports_pkey RENAME TO ingest_receipts_pkey;
-- expand-contract-ok: index name follows the table rename; no code names it
ALTER INDEX idx_finding_imports_tenant_created RENAME TO idx_ingest_receipts_tenant_created;
-- expand-contract-ok: constraint name follows the table rename; no code names it
ALTER TABLE ingest_receipts RENAME CONSTRAINT finding_imports_actor_user_id_fkey TO ingest_receipts_actor_user_id_fkey;
-- expand-contract-ok: constraint name follows the table rename; no code names it
ALTER TABLE ingest_receipts RENAME CONSTRAINT finding_imports_tenant_id_fkey TO ingest_receipts_tenant_id_fkey;
-- expand-contract-ok: constraint name follows the table rename; no code names it
ALTER TABLE ingest_receipts RENAME CONSTRAINT chk_finding_imports_counts TO chk_ingest_receipts_upload_counts;
-- expand-contract-ok: constraint name follows the table rename; no code names it
ALTER TABLE ingest_receipts RENAME CONSTRAINT chk_finding_imports_sha TO chk_ingest_receipts_sha;

-- A run receipt has no file: format and the file name hash are upload-only.
ALTER TABLE ingest_receipts ALTER COLUMN format DROP NOT NULL;
ALTER TABLE ingest_receipts ALTER COLUMN filename_sha256 DROP NOT NULL;

ALTER TABLE ingest_receipts
    ADD COLUMN IF NOT EXISTS source_kind        varchar(16)  NOT NULL DEFAULT 'upload',
    ADD COLUMN IF NOT EXISTS source_ref         varchar(128),
    ADD COLUMN IF NOT EXISTS tool_name          varchar(100),
    ADD COLUMN IF NOT EXISTS coverage           varchar(8)   NOT NULL DEFAULT 'partial',
    ADD COLUMN IF NOT EXISTS coverage_note      varchar(32),
    ADD COLUMN IF NOT EXISTS status             varchar(12)  NOT NULL DEFAULT 'completed',
    ADD COLUMN IF NOT EXISTS reports            integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_received  integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_reopened  integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_closed    integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_untouched integer,
    ADD COLUMN IF NOT EXISTS findings_failed    integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_suppressed integer     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS actions_recorded   integer      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS actions_truncated  boolean      NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS errors             jsonb        NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS updated_at         timestamptz  NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS finished_at        timestamptz;

-- The existing rows are upload receipts of one file each; they finished
-- when they were recorded.
UPDATE ingest_receipts
SET source_ref = id::text, updated_at = created_at, finished_at = created_at, reports = 1,
    findings_received = findings_created + findings_updated
WHERE source_ref IS NULL;
ALTER TABLE ingest_receipts ALTER COLUMN source_ref SET NOT NULL;

ALTER TABLE ingest_receipts
    ADD CONSTRAINT chk_ingest_receipts_source_kind
        CHECK (source_kind IN ('upload', 'scan_run', 'command', 'ci_run', 'connector', 'sensor')),
    ADD CONSTRAINT chk_ingest_receipts_coverage CHECK (coverage IN ('partial', 'full')),
    ADD CONSTRAINT chk_ingest_receipts_status CHECK (status IN ('processing', 'completed', 'failed')),
    ADD CONSTRAINT chk_ingest_receipts_counts CHECK (reports >= 0 AND findings_received >= 0
        AND findings_reopened >= 0 AND findings_closed >= 0 AND findings_failed >= 0
        AND findings_suppressed >= 0 AND actions_recorded >= 0
        AND (findings_untouched IS NULL OR findings_untouched >= 0)),
    ADD CONSTRAINT chk_ingest_receipts_errors CHECK (jsonb_typeof(errors) = 'array'),
    ADD CONSTRAINT ux_ingest_receipts_source UNIQUE (tenant_id, source_kind, source_ref);

CREATE INDEX IF NOT EXISTS idx_ingest_receipts_retention ON ingest_receipts (updated_at)
    WHERE source_kind <> 'upload';

COMMENT ON TABLE ingest_receipts IS
    'One receipt per upload (POST /findings/imports) and per sensor run (scan run, command, CI run, connector sync, unsolicited sensor report): what it did to the tenant''s findings. An upload receipt''s id is the producer of the findings (scan_id) and assets (import_id) it wrote. Counts are organization-wide; readers without an organization view see only their own uploads.';
COMMENT ON COLUMN ingest_receipts.source_ref IS
    'The run, command, CI run or connector run id the receipt counts (its own id for an upload). Unique per tenant and source_kind.';
COMMENT ON COLUMN ingest_receipts.coverage IS
    'full only when the source declared and proved full coverage of an explicit scope (a covered scan, a full-coverage import); only then can findings_closed and findings_untouched be non-zero/non-null.';
COMMENT ON COLUMN ingest_receipts.findings_updated IS
    'Still detected: existing open findings the source reported again.';
COMMENT ON COLUMN ingest_receipts.findings_untouched IS
    'Open findings in the declared scope the source neither reported nor closed; NULL when no scope was declared (partial coverage).';
COMMENT ON COLUMN ingest_receipts.errors IS
    'Up to 100 {index, code} entries (fixed codes, never free text from the report).';
COMMENT ON COLUMN ingest_receipts.filename_sha256 IS
    'SHA-256 of the uploaded file name (uploads only); the name itself is kept only in the audit log.';

-- Per-finding action log: which findings a receipt created, saw again,
-- reopened or closed. One row per (receipt, finding); the first action a
-- receipt recorded for a finding wins.
CREATE TABLE IF NOT EXISTS finding_ingest_actions (
    tenant_id  uuid        NOT NULL,
    receipt_id uuid        NOT NULL,
    finding_id uuid        NOT NULL,
    action     varchar(16) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_finding_ingest_actions PRIMARY KEY (receipt_id, finding_id),
    CONSTRAINT fk_finding_ingest_actions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_ingest_actions_receipt FOREIGN KEY (receipt_id) REFERENCES ingest_receipts (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_ingest_actions_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_ingest_actions_action CHECK (action IN ('created', 'still_detected', 'reopened', 'closed'))
);
COMMENT ON TABLE finding_ingest_actions IS
    'What one receipt did to one finding (created, still_detected, reopened, closed). At most 50,000 rows per receipt (ingest_receipts.actions_truncated beyond); rows older than 90 days are purged.';

-- Leads with finding_id: the ON DELETE CASCADE from findings (and the merge
-- of a finding) look rows up by finding_id alone; a finding's history reads
-- add tenant_id as a filter.
CREATE INDEX IF NOT EXISTS idx_finding_ingest_actions_finding
    ON finding_ingest_actions (finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_ingest_actions_created ON finding_ingest_actions (created_at);

-- One row per command whose run proved coverage of the assets it scanned
-- (the coverage rules of the ingest service): what it left untouched. The
-- receipt's findings_untouched is their sum; a decision evaluated twice
-- replaces its row instead of adding to the sum.
CREATE TABLE IF NOT EXISTS ingest_receipt_coverage (
    tenant_id   uuid        NOT NULL,
    receipt_id  uuid        NOT NULL,
    command_id  uuid        NOT NULL,
    note        varchar(32) NOT NULL,
    untouched   integer     NOT NULL,
    decided_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ingest_receipt_coverage PRIMARY KEY (receipt_id, command_id),
    CONSTRAINT fk_ingest_receipt_coverage_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_ingest_receipt_coverage_receipt FOREIGN KEY (receipt_id) REFERENCES ingest_receipts (id) ON DELETE CASCADE,
    CONSTRAINT chk_ingest_receipt_coverage_untouched CHECK (untouched >= 0)
);
COMMENT ON TABLE ingest_receipt_coverage IS
    'Per receipt and command: the coverage decision (resolved, held, dry_run) and the open findings of the covered scope the run neither reported nor closed.';
CREATE INDEX IF NOT EXISTS idx_ingest_receipt_coverage_tenant ON ingest_receipt_coverage (tenant_id);

-- Daily ingest outcome per source kind and tool, for the dashboards. One
-- upsert per recorded receipt delta; kept 13 months.
CREATE TABLE IF NOT EXISTS dash_ingest_day (
    tenant_id      uuid         NOT NULL,
    day            date         NOT NULL,
    source_kind    varchar(16)  NOT NULL,
    tool           varchar(100) NOT NULL,
    reports        integer      NOT NULL DEFAULT 0,
    received       integer      NOT NULL DEFAULT 0,
    created        integer      NOT NULL DEFAULT 0,
    still_detected integer      NOT NULL DEFAULT 0,
    reopened       integer      NOT NULL DEFAULT 0,
    closed         integer      NOT NULL DEFAULT 0,
    skipped        integer      NOT NULL DEFAULT 0,
    failed         integer      NOT NULL DEFAULT 0,
    suppressed     integer      NOT NULL DEFAULT 0,
    CONSTRAINT pk_dash_ingest_day PRIMARY KEY (tenant_id, day, source_kind, tool),
    CONSTRAINT fk_dash_ingest_day_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_ingest_day_kind CHECK (source_kind IN ('sensor', 'import', 'connector', 'ci')),
    CONSTRAINT chk_dash_ingest_day_counts CHECK (reports >= 0 AND received >= 0 AND created >= 0
        AND still_detected >= 0 AND reopened >= 0 AND closed >= 0 AND skipped >= 0 AND failed >= 0
        AND suppressed >= 0)
);
COMMENT ON TABLE dash_ingest_day IS
    'Dashboard fact: per tenant, day (UTC), source kind and tool, what ingest did (reports, findings received, created, still detected, reopened, closed, skipped, failed, suppressed). Written with the receipts; rows older than 13 months are purged. Organization-wide figures.';

CREATE INDEX IF NOT EXISTS idx_dash_ingest_day_day ON dash_ingest_day (day);

-- Row-level security policies in shadow mode, like the other tenant tables.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['finding_ingest_actions', 'ingest_receipt_coverage', 'dash_ingest_day'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
