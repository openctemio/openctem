-- Add created_by column to findings for pentest ownership tracking.
-- RFC Campaign Team Roles & RBAC (§ Ownership Rules): delete/edit gates on
-- created_by for testers. Previously unified findings had no creator concept
-- so only lead could delete in practice — incomplete ownership semantics.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Partial index for ownership lookups (only populated for manually-authored findings).
CREATE INDEX IF NOT EXISTS idx_findings_created_by
    ON findings(created_by)
    WHERE created_by IS NOT NULL;
