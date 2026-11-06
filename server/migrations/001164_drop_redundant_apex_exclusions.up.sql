-- Drop the apex exclusions that the wildcard rule change made redundant
-- (research/53 §6.1, owner decision SC6).
--
-- Migration 000292 (squashed into the baseline) added an apex sibling "x"
-- for every wildcard exclusion "*.x" / "**.x" when "*.x" meant "the
-- subdomains only". Since RFC-054 S1, "*.x" covers x itself, so a sibling is
-- redundant while its wildcard parent is in effect at least as long:
--
--   * the sibling is the untouched 000292 row (created_by
--     'system:migration-000292', its split reason, never updated since);
--   * both are active, the parent is approved (an exclusion in effect), and
--     the parent never expires or expires no earlier than the sibling.
--
-- Every other sibling (its parent was removed, deactivated, shortened or is
-- still pending, or a person changed the sibling) is a real exclusion now:
-- it stays, and its system reason is rewritten to say what it is.
--
-- No audit_logs row is written here: the audit log is hash-chained by the
-- application, and a row inserted from SQL would read as a chain break. The
-- changelog fragment documents the change.

DELETE FROM scope_exclusions c
USING scope_exclusions p
WHERE c.created_by = 'system:migration-000292'
  AND c.reason LIKE 'Split from wildcard exclusion %'
  AND c.updated_at = c.created_at
  AND c.status = 'active'
  AND c.exclusion_type IN ('domain', 'subdomain')
  AND p.tenant_id = c.tenant_id
  AND p.id <> c.id
  AND p.exclusion_type IN ('domain', 'subdomain')
  AND lower(rtrim(p.pattern, '.')) IN ('*.' || lower(rtrim(c.pattern, '.')), '**.' || lower(rtrim(c.pattern, '.')))
  AND p.status = 'active'
  AND p.approved_at IS NOT NULL
  AND (p.expires_at IS NULL OR (c.expires_at IS NOT NULL AND p.expires_at >= c.expires_at));

-- The siblings that stay: say what they are now. The parent's pattern and
-- id and the original reason are kept, so the down migration can restore
-- the 000292 wording exactly.
UPDATE scope_exclusions
SET reason = LEFT(
        'Apex of the former wildcard exclusion '
        || substring(reason FROM '^Split from wildcard exclusion (\S+ \([0-9a-fA-F-]+\))')
        || ', kept as its own exclusion when the wildcard rule changed (2026-10). Original reason: '
        || COALESCE(substring(reason FROM 'Original reason: (.*)$'), ''),
        10000)
WHERE created_by = 'system:migration-000292'
  AND reason ~ '^Split from wildcard exclusion \S+ \([0-9a-fA-F-]+\)';
