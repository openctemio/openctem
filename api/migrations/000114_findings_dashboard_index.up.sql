-- Partial composite index for the CTEM dashboard stats query.
--
-- The dashboard repository excludes pentest 'draft' and 'in_review' findings
-- (Phase 4 internal workflow) from every aggregate via:
--   WHERE tenant_id = $1 AND status NOT IN ('draft', 'in_review')
--
-- Without this index, large tenants pay a sequential scan + filter on every
-- dashboard load. The partial index lets PG plan an index-only scan over the
-- post-filter set, which is what we actually want.
--
-- Partial = rows where status NOT IN ('draft', 'in_review'), so the index is
-- much smaller than a full (tenant_id, status) index for tenants with many
-- in-progress pentest drafts.

CREATE INDEX IF NOT EXISTS idx_findings_dashboard
    ON findings(tenant_id, status)
    WHERE status NOT IN ('draft', 'in_review');
