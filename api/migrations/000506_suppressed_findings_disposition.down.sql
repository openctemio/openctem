-- Revert 000506: suppressed findings go back to resolved / suppressed, as the
-- old ingest wrote them. Only rows a suppression rule closed (resolution
-- 'suppressed' with a recorded rule) are touched.
UPDATE findings f
SET status = 'resolved',
    updated_at = NOW()
WHERE f.resolution = 'suppressed'
  AND f.status IN ('false_positive', 'accepted')
  AND EXISTS (SELECT 1 FROM finding_suppressions fs WHERE fs.finding_id = f.id);
