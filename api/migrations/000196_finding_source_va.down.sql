-- Remove 'va'.
--
-- Narrowing a CHECK fails if any row already uses the value, which is correct:
-- rolling back after VA findings exist would orphan them. Reassign or delete
-- those rows first, deliberately.
--
-- expand-contract-ok: this is the down leg of an expand-only migration; it runs
-- only on an explicit rollback, never during a forward deploy.

DELETE FROM finding_sources WHERE code = 'va';
DELETE FROM finding_source_categories WHERE code = 'vulnerability_assessment';

-- The constraint is named chk_findings_source (migration 000012), not the
-- Postgres-default findings_source_check. Dropping the wrong name silently
-- leaves the original in place and adds a second one, and a row then has to
-- satisfy both — which is exactly how this migration first failed its own
-- parity test.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source;

ALTER TABLE findings ADD CONSTRAINT chk_findings_source
    CHECK (source IN (
        'sast', 'dast', 'sca', 'secret', 'iac', 'container',
        'cspm', 'easm',
        'rasp', 'waf', 'siem',
        'manual', 'pentest', 'bug_bounty', 'red_team',
        'external', 'threat_intel', 'vendor',
        'sarif', 'sca_tool', 'api'
    ));
