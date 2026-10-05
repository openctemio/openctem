-- expand-contract-ok: contract step; no released code reads or writes these columns (none of them appears in api, web, sensor or sdk-go), so pods of the previous release are unaffected.
-- Drop columns nothing reads or writes (legacy cleanup, wave 5).
--
-- Checked on a restore of production data at develop head and against the
-- api, web, sensor and sdk-go sources (no reference outside migrations):
--
--   * assets.freshness_status (000151): meant for an SLA controller that was
--     never built; every row holds the default "fresh". Staleness is
--     assets.status = 'stale' (asset lifecycle worker).
--   * assets.compliance_requirements, assets.last_assessment_at,
--     assets.next_assessment_at (000008): never written; NULL on every row.
--   * pipeline_templates.ui_positions (000018): never written; every row
--     holds the default {}.
--
-- No data is lost: the only values present are the column defaults.

ALTER TABLE assets
    DROP COLUMN IF EXISTS freshness_status,
    DROP COLUMN IF EXISTS compliance_requirements,
    DROP COLUMN IF EXISTS last_assessment_at,
    DROP COLUMN IF EXISTS next_assessment_at;

ALTER TABLE pipeline_templates DROP COLUMN IF EXISTS ui_positions;
