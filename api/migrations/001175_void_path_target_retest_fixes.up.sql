-- Void the "fixed" retests that re-ran a template with the finding's
-- matched-at URL as its input.
--
-- Until this release a retest passed the matched-at URL
-- (https://host/wp-admin/js/theme.js) to the template as its input. A
-- template builds its request from the input ({{BaseURL}}/wp-admin/js/theme.js),
-- so the re-run requested the path twice, got a 404 and reported "did not
-- match", which the platform read as fixed. Those outcomes prove nothing.
--
-- For each such retest that is still the finding's latest one and whose
-- resolution the finding still carries, the finding returns to the status it
-- had before the retest and the retest becomes "unknown" with the reason.
-- Retests whose target was a bare host or an origin are untouched.

WITH voided AS (
    SELECT r.id, r.tenant_id, r.finding_id, r.prior_status
    FROM finding_retests r
    JOIN findings f ON f.tenant_id = r.tenant_id AND f.id = r.finding_id
    WHERE r.status = 'completed'
      AND r.outcome = 'fixed'
      AND r.target ~* '^https?://[^/?#]+[/?#].*[^/]'
      AND r.prior_status IS NOT NULL
      AND r.prior_status <> 'resolved'
      AND r.result_status = 'resolved'
      AND f.status = 'resolved'
      AND f.resolution_method = 'retest_verified'
      AND NOT EXISTS (
          SELECT 1 FROM finding_retests later
          WHERE later.tenant_id = r.tenant_id AND later.finding_id = r.finding_id
            AND later.created_at > r.created_at
      )
),
reopened AS (
    UPDATE findings f
    SET status = v.prior_status,
        resolution = NULL, resolution_method = NULL,
        resolved_at = NULL, resolved_by = NULL,
        updated_at = NOW()
    FROM voided v
    WHERE f.tenant_id = v.tenant_id AND f.id = v.finding_id
    RETURNING f.id
)
UPDATE finding_retests r
SET outcome = 'unknown',
    result_status = r.prior_status,
    reason = 'voided: this retest re-ran the template with the matched-at URL as its input, '
          || 'so it requested the path twice and could not match; the finding returned to '
          || r.prior_status || '. Retest again.'
FROM voided v
WHERE r.id = v.id;
