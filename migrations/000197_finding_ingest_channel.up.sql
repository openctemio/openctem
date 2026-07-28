-- Record which channel reported a finding, separately from which technique
-- found it.
--
-- findings.source answers "how was this found" — sast, dast, va, easm. It does
-- not answer "who told us", and the two were conflated: a Tenable import and an
-- agent scan were indistinguishable afterwards. See
-- docs/architecture/decisions/004-finding-provenance.md for why a single
-- integration_id column is the wrong shape and this is the right first step.
--
-- Reuses the source_type enum from migration 000014 rather than inventing a
-- parallel vocabulary. Its four values already match ctis.ReportMetadata's
-- SourceType, which the ingest pipeline has been carrying and discarding.
--
-- Nullable with no default. A NULL means "we did not record it", which is the
-- truth for every row written before this migration; defaulting to 'scanner'
-- would assert something about historical rows that nobody verified.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS ingest_channel source_type;

COMMENT ON COLUMN findings.ingest_channel IS
    'Which channel reported this finding: integration | collector | scanner | manual. '
    'Distinct from findings.source, which records the technique. NULL means unrecorded '
    '(written before migration 000197).';

-- Backfill from what the existing columns can prove, and only that.
--
-- agent_id is set only by the CTIS ingest path authenticated with an agent API
-- key, so it is direct evidence of a scanner channel.
UPDATE findings SET ingest_channel = 'scanner'
WHERE ingest_channel IS NULL AND agent_id IS NOT NULL;

-- These sources are set by exactly one code path each and that path is a human
-- entering data: the REST create handler, the pentest module, and the Burp/CSV
-- importers which stamp 'pentest' unconditionally.
UPDATE findings SET ingest_channel = 'manual'
WHERE ingest_channel IS NULL
  AND source IN ('manual', 'pentest', 'bug_bounty', 'red_team');

-- Deliberately no rule for the rest. A row with source='sast' and no agent_id
-- could be a Semgrep result posted to /agent/ingest, a DefectDojo sync, or a
-- Tenable upload — the mapper's old default erased the difference, and guessing
-- now would launder that erasure into something that looks like data. They stay
-- NULL, and the UI shows them as unknown rather than as a confident wrong
-- answer.

-- CONCURRENTLY is safe here, despite what migrations 000096 and 000099 claim.
-- Both assert that "golang-migrate runs each file in a transaction, and CREATE
-- INDEX CONCURRENTLY cannot run inside one". The second half is true; the first
-- is not, and the evidence is in the database: seven up-migrations use
-- CONCURRENTLY, 000143 among them, and idx_findings_sla_overdue exists on a
-- deployment sitting at version 194. Wrapping the files in a transaction was
-- tested locally and 000143 fails immediately, so the runner demonstrably does
-- not wrap them.
--
-- It matters because findings is one of the largest tables here and a plain
-- CREATE INDEX would hold a write lock for the whole build.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_ingest_channel
    ON findings (tenant_id, ingest_channel)
    WHERE ingest_channel IS NOT NULL;
