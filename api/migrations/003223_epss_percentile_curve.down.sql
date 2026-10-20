ALTER TABLE epss_scores ADD COLUMN percentile numeric(9,6);
ALTER TABLE epss_scores ADD COLUMN score_date date;

UPDATE epss_scores e
SET percentile = c.percentile
FROM epss_percentile_curve c
WHERE c.score = e.epss_score;

UPDATE epss_scores
SET score_date = COALESCE(
    (SELECT data_date FROM threat_intel_sync_status WHERE source_name = 'epss'),
    CURRENT_DATE);

ALTER TABLE epss_scores ALTER COLUMN score_date SET NOT NULL;

CREATE INDEX idx_epss_scores_percentile ON epss_scores USING btree (percentile DESC);
CREATE INDEX idx_epss_scores_date ON epss_scores USING btree (score_date DESC);

ALTER TABLE threat_intel_sync_status DROP COLUMN IF EXISTS data_date;
DROP TABLE IF EXISTS epss_percentile_curve;
