-- An AI application connected over MCP can propose a false positive or an
-- accepted risk for the person who connected it (docs/rfcs/RFC-062-mcp-authorization.md,
-- "Proposal tools"). The request is that person's own (requested_by is set),
-- so the four-eyes rule refuses them as its approver; requested_via names the
-- AI application that wrote it, for the approver and the audit trail.
--
-- requested_by is not checked: it becomes NULL when the person is deleted.
--
-- Live impact: a nullable column (no rewrite) and a NOT VALID check on it.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS requested_via text;

ALTER TABLE finding_status_approvals
    DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_requested_via;
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_requested_via
    CHECK (requested_via IS NULL OR (requested_by_actor IS NULL AND char_length(requested_via) BETWEEN 1 AND 200)) NOT VALID;

COMMENT ON COLUMN finding_status_approvals.requested_via IS
    'AI application (MCP client name) that made this request for requested_by; NULL when the person made it themselves';
