CREATE INDEX IF NOT EXISTS idx_ticket_create_holds_finding
    ON ticket_create_holds (tenant_id, finding_id);
DROP INDEX IF EXISTS idx_ticket_create_holds_finding_checked;
