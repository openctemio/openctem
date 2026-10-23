-- Reverts 003380_ingest_dispositions. Side-effect jobs are dropped (their
-- automations are not started); suppressed and held action rows are dropped.
DELETE FROM ingest_jobs WHERE kind = 'side_effects';
ALTER TABLE ingest_jobs DROP CONSTRAINT IF EXISTS chk_ingest_jobs_kind;
ALTER TABLE ingest_jobs
    ADD CONSTRAINT chk_ingest_jobs_kind CHECK (kind IN ('sensor', 'ci_results', 'finding_import'));

DROP TRIGGER IF EXISTS trg_scope_exclusions_policy_version ON scope_exclusions;
DROP TRIGGER IF EXISTS trg_suppression_rules_policy_version ON suppression_rules;
DROP FUNCTION IF EXISTS bump_ingest_policy_version();
DROP TABLE IF EXISTS ingest_policy_versions;
DROP TABLE IF EXISTS ingest_receipt_items;

DELETE FROM finding_ingest_actions WHERE action IN ('suppressed', 'held');
ALTER TABLE finding_ingest_actions
    DROP COLUMN IF EXISTS policy_version,
    DROP COLUMN IF EXISTS policy_id,
    DROP COLUMN IF EXISTS policy;
ALTER TABLE finding_ingest_actions DROP CONSTRAINT IF EXISTS chk_finding_ingest_actions_action;
ALTER TABLE finding_ingest_actions
    ADD CONSTRAINT chk_finding_ingest_actions_action
        CHECK (action IN ('created', 'still_detected', 'reopened', 'closed'));
