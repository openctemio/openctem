-- The release job's due-holds query joins held findings by (tenant_id,
-- finding_id) and compares checked_at; one index covers both, and replaces the
-- narrower finding index it starts with.
CREATE INDEX IF NOT EXISTS idx_ticket_create_holds_finding_checked
    ON ticket_create_holds (tenant_id, finding_id, checked_at);
DROP INDEX IF EXISTS idx_ticket_create_holds_finding;
