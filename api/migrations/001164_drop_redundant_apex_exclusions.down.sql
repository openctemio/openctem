-- Undo 001164: restore the 000292 wording on the siblings that stayed, and
-- re-create the deleted siblings by the original 000292 rule (an apex row
-- for every non-rejected domain/subdomain wildcard exclusion that has none,
-- copying its status, approval, rejection and expiry). The rule is
-- deterministic, so up -> down -> up converges. No audit_logs rows (see the
-- up migration).

UPDATE scope_exclusions
SET reason = LEFT(
        'Split from wildcard exclusion '
        || substring(reason FROM '^Apex of the former wildcard exclusion (\S+ \([0-9a-fA-F-]+\))')
        || ': "*.x" no longer covers "x" itself, so the apex keeps its exclusion. Original reason: '
        || COALESCE(substring(reason FROM 'Original reason: (.*)$'), ''),
        10000)
WHERE created_by = 'system:migration-000292'
  AND reason ~ '^Apex of the former wildcard exclusion \S+ \([0-9a-fA-F-]+\)';

INSERT INTO scope_exclusions (
    tenant_id, exclusion_type, pattern, reason, status, expires_at,
    approved_by, approved_at, rejected_by, rejected_at,
    created_by, created_at, updated_at
)
SELECT DISTINCT ON (w.tenant_id, w.exclusion_type, w.apex)
    w.tenant_id,
    w.exclusion_type,
    w.apex,
    LEFT(
        'Split from wildcard exclusion ' || w.pattern || ' (' || w.id::text ||
        '): "*.x" no longer covers "x" itself, so the apex keeps its exclusion. Original reason: ' ||
        COALESCE(w.reason, ''),
        10000
    ),
    w.status,
    w.expires_at,
    w.approved_by,
    w.approved_at,
    w.rejected_by,
    w.rejected_at,
    'system:migration-000292',
    w.now_ts,
    w.now_ts
FROM (
    SELECT e.*,
           RTRIM(LOWER(REGEXP_REPLACE(e.pattern, '^\*\*?\.', '')), '.') AS apex,
           NOW() AS now_ts
    FROM scope_exclusions e
    WHERE e.exclusion_type IN ('domain', 'subdomain')
      AND (e.pattern LIKE '*.%' OR e.pattern LIKE '**.%')
      AND COALESCE(e.status, '') <> 'rejected'
) w
WHERE w.apex <> ''
  AND NOT EXISTS (
      SELECT 1 FROM scope_exclusions x
      WHERE x.tenant_id = w.tenant_id
        AND x.exclusion_type = w.exclusion_type
        AND RTRIM(LOWER(x.pattern), '.') = w.apex
  )
ORDER BY w.tenant_id, w.exclusion_type, w.apex,
         (w.status = 'active') DESC, w.created_at
ON CONFLICT (tenant_id, exclusion_type, pattern) DO NOTHING;
