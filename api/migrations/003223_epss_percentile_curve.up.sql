-- expand-contract-ok: contract step; the percentile and score_date columns are replaced by the curve table and the sync status row in the same release, and the API is stopped for this upgrade
-- EPSS percentile is a rank that moves for almost every CVE on every daily
-- feed, while the score moves for about 1 %. Stored per row it forced a
-- rewrite of the whole table (and a fan-out to the catalog and findings) each
-- day. It is now one row per distinct score; a CVE's percentile is the curve
-- value at its score. The feed date moves to the sync status row.

CREATE TABLE epss_percentile_curve (
    score      numeric(8,6) PRIMARY KEY,
    percentile numeric(9,6) NOT NULL
);

COMMENT ON TABLE epss_percentile_curve IS
    'EPSS percentile (0-100) per distinct score, replaced by each feed sync; epss_scores no longer stores it';

INSERT INTO epss_percentile_curve (score, percentile)
SELECT epss_score, MAX(percentile)
FROM epss_scores
WHERE percentile IS NOT NULL
GROUP BY epss_score;

ALTER TABLE threat_intel_sync_status ADD COLUMN IF NOT EXISTS data_date date;

COMMENT ON COLUMN threat_intel_sync_status.data_date IS
    'Date stamped on the newest feed the source delivered (EPSS score_date)';

UPDATE threat_intel_sync_status
SET data_date = (SELECT MAX(score_date) FROM epss_scores)
WHERE source_name = 'epss';

DROP INDEX IF EXISTS idx_epss_scores_percentile;
DROP INDEX IF EXISTS idx_epss_scores_date;

ALTER TABLE epss_scores DROP COLUMN percentile;
ALTER TABLE epss_scores DROP COLUMN score_date;
