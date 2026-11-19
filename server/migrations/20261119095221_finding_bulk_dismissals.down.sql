-- Reverts finding_bulk_dismissals. Approval groups made by a bulk dismiss
-- (source type 'selection') are never deleted here: while any exists the
-- down stops with an error, so their decisions and history are kept. Close or
-- export them first.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM approval_batches WHERE source_type = 'selection') THEN
        RAISE EXCEPTION 'approval_batches has rows with source_type selection (bulk dismiss groups); they are kept, so this down migration stops';
    END IF;
END $$;

ALTER TABLE approval_batches DROP CONSTRAINT IF EXISTS chk_approval_batches_source;
ALTER TABLE approval_batches ADD CONSTRAINT chk_approval_batches_source
    CHECK (source_type IN ('remediation_task', 'vulnerability_selection'));

DROP TABLE IF EXISTS finding_bulk_dismissals;
