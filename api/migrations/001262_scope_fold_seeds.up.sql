-- Seeds and verified domains fold into scope entries (research/53 A1,
-- owner decisions SC1 and SC2; RFC-054 §4.2).
--
-- After this, only scope entries authorize active probes; a verified domain
-- is proof of control only. Today's authority is kept exactly, except that a
-- domain verified for SSO sign-in no longer authorizes (that narrowing
-- already shipped with RFC-054 and is not undone here):
--
--   * a root-domain seed v authorized T1 probes of v and every name below
--     it: it becomes the permanent entry "*.v" (t1, active, no approvals),
--     unless an active permanent wildcard entry already covers v;
--   * an easm-purpose verified domain d did the same: it becomes "*.d" under
--     the same rule;
--   * discovery (Certificate Transparency watch) hangs off the entry: the new
--     column discovery, on for permanent domain entries, off for one-off and
--     non-domain entries (a one-off never confirms names, so its names would
--     only be review noise).
--
-- No audit_logs rows from SQL (the audit log is hash-chained by the
-- application); the changelog fragment records the change.
--
-- expand-contract-ok: contract step; easm_seeds is folded into scope_targets
-- above and no code reads or writes it after this release (the down
-- migration recreates it from the folded entries).

ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS discovery boolean NOT NULL DEFAULT true;
UPDATE scope_targets SET discovery = false
WHERE discovery AND (expires_at IS NOT NULL OR target_type NOT IN ('domain', 'subdomain'));

-- 1. A seed whose exact wildcard entry is already active and permanent:
--    the entry keeps authorizing; it takes the seed's discovery and at least
--    the seed's tier (T1).
UPDATE scope_targets t
SET discovery = t.discovery OR s.discovery_enabled,
    max_tier = GREATEST(t.max_tier, 1)
FROM easm_seeds s
WHERE s.kind = 'root_domain'
  AND t.tenant_id = s.tenant_id
  AND t.target_type IN ('domain', 'subdomain')
  AND lower(t.pattern) IN ('*.' || lower(s.value), '**.' || lower(s.value))
  AND t.status = 'active' AND t.expires_at IS NULL;

-- 2. Every other seed not already covered by an active permanent wildcard
--    entry becomes "*.v". A "*.v" row that exists but does not authorize
--    (inactive, pending, rejected, expiring) is put back into effect: the
--    seed authorized v until now, so nothing new is allowed.
INSERT INTO scope_targets (
    tenant_id, target_type, pattern, description, priority, status, tags,
    created_by, created_at, updated_at,
    expires_at, reason, max_tier, approvals_required, approved_at, origin, discovery)
SELECT s.tenant_id, 'domain', '*.' || lower(s.value), s.label, 0, 'active', '{}',
       COALESCE(s.created_by::text, 'system:seed-migration'), s.created_at, now(),
       NULL, 'Root-domain seed ' || lower(s.value) || ', attested ' || to_char(s.attested_at, 'YYYY-MM-DD'),
       1, 0, s.attested_at, 'seed_migration', s.discovery_enabled
FROM easm_seeds s
WHERE s.kind = 'root_domain'
  AND NOT EXISTS (
      SELECT 1 FROM scope_targets t
      WHERE t.tenant_id = s.tenant_id
        AND t.target_type IN ('domain', 'subdomain')
        AND t.status = 'active' AND t.expires_at IS NULL
        AND t.pattern ~ '^\*\*?\.'
        AND (lower(s.value) = regexp_replace(lower(t.pattern), '^\*\*?\.', '')
             OR right(lower(s.value), length(regexp_replace(t.pattern, '^\*\*?\.', '')) + 1)
                = '.' || regexp_replace(lower(t.pattern), '^\*\*?\.', '')))
ON CONFLICT (tenant_id, target_type, pattern) DO UPDATE
SET status = 'active', expires_at = NULL, approvals_required = 0,
    approved_at = COALESCE(scope_targets.approved_at, EXCLUDED.approved_at),
    max_tier = GREATEST(scope_targets.max_tier, 1),
    discovery = scope_targets.discovery OR EXCLUDED.discovery,
    rejected_by = NULL, rejected_at = NULL;

-- 3. An easm-purpose verified domain not covered by an active permanent
--    wildcard entry (after step 2) becomes "*.d" the same way.
INSERT INTO scope_targets (
    tenant_id, target_type, pattern, description, priority, status, tags,
    created_by, created_at, updated_at,
    expires_at, reason, max_tier, approvals_required, approved_at, origin, discovery)
SELECT v.tenant_id, 'domain', '*.' || lower(v.domain), '', 0, 'active', '{}',
       'system:seed-migration', now(), now(),
       NULL, 'Verified domain ' || lower(v.domain), 1, 0, COALESCE(v.verified_at, now()), 'seed_migration', true
FROM verified_domains v
WHERE v.purpose = 'easm' AND v.status = 'verified'
  AND NOT EXISTS (
      SELECT 1 FROM scope_targets t
      WHERE t.tenant_id = v.tenant_id
        AND t.target_type IN ('domain', 'subdomain')
        AND t.status = 'active' AND t.expires_at IS NULL
        AND t.pattern ~ '^\*\*?\.'
        AND (lower(v.domain) = regexp_replace(lower(t.pattern), '^\*\*?\.', '')
             OR right(lower(v.domain), length(regexp_replace(t.pattern, '^\*\*?\.', '')) + 1)
                = '.' || regexp_replace(lower(t.pattern), '^\*\*?\.', '')))
ON CONFLICT (tenant_id, target_type, pattern) DO UPDATE
SET status = 'active', expires_at = NULL, approvals_required = 0,
    approved_at = COALESCE(scope_targets.approved_at, EXCLUDED.approved_at),
    max_tier = GREATEST(scope_targets.max_tier, 1),
    discovery = true,
    rejected_by = NULL, rejected_at = NULL;

DROP TABLE IF EXISTS easm_seeds;
