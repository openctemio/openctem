ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_closure;
ALTER TABLE finding_status_approvals DROP COLUMN IF EXISTS closure_reason;
DROP FUNCTION IF EXISTS finding_closure_valid(text, text, text);
ALTER TABLE findings DROP COLUMN IF EXISTS closure_reason, DROP COLUMN IF EXISTS verification;
