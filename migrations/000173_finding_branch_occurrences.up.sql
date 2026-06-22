-- Branch-aware findings: occurrence model (Phase 1, additive).
--
-- A finding keeps its branch-independent identity (UNIQUE(tenant_id, fingerprint));
-- this table records, per branch, where that finding has been observed. One
-- finding present on `main` and a feature branch is ONE findings row with TWO
-- occurrence rows — preserving cross-branch correlation while enabling accurate
-- per-branch views and per-branch lifecycle.
--
-- This migration is purely additive: nothing reads occurrences yet (the ingest
-- pipeline dual-writes them and existing branch_id data is backfilled). Read
-- paths cut over in later phases.

CREATE TABLE IF NOT EXISTS finding_branch_occurrences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    branch_id UUID NOT NULL REFERENCES repository_branches(id) ON DELETE CASCADE,
    -- denormalized repository (= branch.repository_id) for cheap per-repo rollups
    repository_id UUID,
    -- scanner-presence lifecycle for THIS branch (distinct from findings.status,
    -- which is the authoritative human/headline decision):
    --   open       — currently present on the branch
    --   auto_fixed  — not seen in the latest full scan of the branch
    --   resolved    — closed (e.g. branch retired)
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_scan_id VARCHAR(100),
    first_commit_sha VARCHAR(64),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_scan_id VARCHAR(100),
    last_commit_sha VARCHAR(64),
    resolved_at TIMESTAMPTZ,
    resolved_reason VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_finding_branch UNIQUE (finding_id, branch_id),
    CONSTRAINT chk_fbo_status CHECK (status IN ('open', 'auto_fixed', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_fbo_tenant_branch_status
    ON finding_branch_occurrences (tenant_id, branch_id, status);
CREATE INDEX IF NOT EXISTS idx_fbo_finding ON finding_branch_occurrences (finding_id);
CREATE INDEX IF NOT EXISTS idx_fbo_repository ON finding_branch_occurrences (repository_id);

-- Backfill from findings that already carry a branch_id (first-scan-wins
-- attribution). This seeds the occurrence truth from existing data without
-- touching the findings rows. Status maps presence: closed-ish finding states
-- → 'resolved', everything else → 'open' (still present on that branch).
INSERT INTO finding_branch_occurrences (
    tenant_id, finding_id, branch_id, repository_id, status,
    first_seen_at, first_seen_scan_id, first_commit_sha,
    last_seen_at, last_seen_scan_id, last_commit_sha
)
SELECT
    f.tenant_id, f.id, f.branch_id, b.repository_id,
    CASE WHEN f.status IN ('resolved', 'false_positive', 'accepted', 'duplicate')
         THEN 'resolved' ELSE 'open' END,
    COALESCE(f.first_detected_at, NOW()), f.scan_id, f.first_detected_commit,
    COALESCE(f.last_seen_at, NOW()), f.scan_id, f.last_seen_commit
FROM findings f
JOIN repository_branches b ON b.id = f.branch_id
WHERE f.branch_id IS NOT NULL
ON CONFLICT (finding_id, branch_id) DO NOTHING;
