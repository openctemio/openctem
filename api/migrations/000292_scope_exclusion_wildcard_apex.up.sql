-- A wildcard exclusion "*.x" no longer excludes the bare name "x"
-- (RFC-042 §6.13, F17): "*.x" now means the subdomains of x only, in scope
-- targets and exclusions alike.
--
-- Existing exclusions keep the meaning they were approved with. For every
-- domain/subdomain exclusion written "*.x" or "**.x", this adds a sibling
-- exclusion for the apex "x" with the same tenant, type, status, approval,
-- rejection and expiry, so nothing that was excluded yesterday is scanned
-- tomorrow. A rejected row gets no sibling (it never took effect).
--
-- Where an apex row already exists (any status) nothing is added: the unique
-- key (tenant_id, exclusion_type, pattern) holds one row per pattern and the
-- tenant has already decided about that name. When both "*.x" and "**.x"
-- exist, the sibling copies the one in effect ('active' first).
--
-- Provenance: created_by is 'system:migration-000292' and the reason names
-- the wildcard row it was split from. No audit_logs row is written here: the
-- audit log is hash-chained by the application (000154), and a row inserted
-- from SQL would be reported by the chain verifier as an unchained entry.

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
    NOW(),
    NOW()
FROM (
    SELECT e.*,
           RTRIM(LOWER(REGEXP_REPLACE(e.pattern, '^\*\*?\.', '')), '.') AS apex
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
