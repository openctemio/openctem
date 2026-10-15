-- Risk snapshots record the scoring versions their numbers were computed
-- with (api/docs/architecture/scoring-versions.md, "History").
--
-- A snapshot is history: it is never recomputed when a scoring model or a
-- tenant's scoring settings change. risk_version is the oldest asset risk
-- version among the tenant's live assets when the snapshot was taken,
-- priority_version the oldest priority version among its open findings, so
-- a trend can tell which days were computed with which model and settings.
-- NULL = taken before versions existed.
--
-- Live impact: two nullable columns on risk_snapshots (no rewrite).

ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS risk_version bigint;
ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS priority_version bigint;

COMMENT ON COLUMN risk_snapshots.risk_version IS
    'Oldest scoring_changes id among the asset risk scores the snapshot averaged; NULL = before versions.';
COMMENT ON COLUMN risk_snapshots.priority_version IS
    'Oldest scoring_changes id among the open findings the snapshot counted by priority; NULL = before versions.';
