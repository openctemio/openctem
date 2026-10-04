-- 000564: suppressed findings carry their disposition, not "resolved"
-- (research 18 F7, owner decision O9).
--
-- Ingest used to close a finding an approved suppression rule matched as
-- status 'resolved' with resolution 'suppressed', so false positives and
-- accepted risks counted as fixes in fix-rate and MTTR. Ingest now writes the
-- rule's disposition; this moves the existing rows.
--
-- Only rows whose provenance is certain move: resolution 'suppressed' is
-- written by ingest suppression alone, and the disposition comes from the
-- rule recorded in finding_suppressions (same tenant). A row with no recorded
-- rule, or with rules that disagree, stays as it is.
--
-- The regression trigger is held off for the relabel: resolved -> accepted is
-- a reclassification, not "fixed and came back". Batched by nothing: the set
-- is small (0 rows on live at the time of writing) and the UPDATE touches only
-- those rows.

ALTER TABLE findings DISABLE TRIGGER trg_findings_mark_regression;

WITH disposition AS (
    SELECT fs.finding_id,
           MIN(CASE sr.suppression_type WHEN 'false_positive' THEN 'false_positive' ELSE 'accepted' END) AS status
    FROM finding_suppressions fs
    JOIN findings f ON f.id = fs.finding_id
    JOIN suppression_rules sr ON sr.id = fs.suppression_rule_id AND sr.tenant_id = f.tenant_id
    WHERE f.status = 'resolved' AND f.resolution = 'suppressed'
    GROUP BY fs.finding_id
    HAVING COUNT(DISTINCT CASE sr.suppression_type WHEN 'false_positive' THEN 'false_positive' ELSE 'accepted' END) = 1
)
UPDATE findings f
SET status = d.status,
    resolution_method = NULL,
    updated_at = NOW()
FROM disposition d
WHERE f.id = d.finding_id
  AND f.status = 'resolved'
  AND f.resolution = 'suppressed';

ALTER TABLE findings ENABLE TRIGGER trg_findings_mark_regression;
