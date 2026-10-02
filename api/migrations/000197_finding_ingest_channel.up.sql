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

-- The index lives in 000198, alone in its own file. golang-migrate wraps a
-- multi-statement file in a transaction and CREATE INDEX CONCURRENTLY cannot
-- run inside one; a single-statement file is not wrapped, which is why 000143
-- gets away with it and this file would not have.
--
-- I learned that the hard way: the first version of this migration carried the
-- index and asserted CONCURRENTLY was fine here, citing seven migrations that
-- "use" it. Six of those only mention it in a comment explaining why they do
-- not. It failed on the live database and left schema_migrations dirty. The
-- transaction did its job — nothing was half-applied — but the claim in the
-- comment was mine and it was wrong.
