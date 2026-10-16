-- findings.sub_status_id always names a sub-status of the finding's own
-- tenant and of its current canonical status: a composite foreign key on
-- (tenant_id, sub_status_id, status) (docs/rfcs/RFC-110-tenant-lifecycles.md).
-- Added NOT VALID (no scan of the populated table under the lock); the
-- validation is its own migration.
ALTER TABLE findings
    ADD CONSTRAINT fk_findings_sub_status FOREIGN KEY (tenant_id, sub_status_id, status)
        REFERENCES lifecycle_sub_statuses (tenant_id, id, canonical_status) NOT VALID;

-- Every writer that moves a finding keeps working unchanged: when the status
-- changes and the writer did not pick a sub-status of the new status, or the
-- closure reason no longer matches the one the sub-status is bound to, the
-- finding falls back to the default label (NULL), so the foreign key never
-- fails. Named to run after the BEFORE triggers that change the status or the
-- closure reason (reopen_orphaned_duplicate, settle_closure).
CREATE OR REPLACE FUNCTION findings_settle_sub_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound record;
BEGIN
    IF NEW.sub_status_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status
       AND NEW.sub_status_id IS NOT DISTINCT FROM OLD.sub_status_id THEN
        NEW.sub_status_id := NULL;
        RETURN NEW;
    END IF;
    SELECT canonical_status, closure_reason INTO bound
    FROM lifecycle_sub_statuses
    WHERE tenant_id = NEW.tenant_id AND id = NEW.sub_status_id;
    IF NOT FOUND OR bound.canonical_status IS DISTINCT FROM NEW.status THEN
        -- Another tenant's or another status's sub-status: the foreign key
        -- refuses it below. A writer that chose one explicitly gets the error.
        IF TG_OP = 'UPDATE' AND NEW.sub_status_id IS NOT DISTINCT FROM OLD.sub_status_id THEN
            NEW.sub_status_id := NULL;
        END IF;
        RETURN NEW;
    END IF;
    IF bound.closure_reason IS NOT NULL AND NEW.closure_reason IS DISTINCT FROM bound.closure_reason THEN
        IF TG_OP = 'UPDATE' AND NEW.sub_status_id IS NOT DISTINCT FROM OLD.sub_status_id THEN
            NEW.sub_status_id := NULL;
        ELSE
            RAISE EXCEPTION 'sub-status % is bound to closure reason %, the finding has %',
                NEW.sub_status_id, bound.closure_reason, COALESCE(NEW.closure_reason, 'none')
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION findings_settle_sub_status() IS
    'Drops a finding sub-status that no longer fits its status or closure reason to the default label (NULL); refuses an explicit mismatching choice';

CREATE TRIGGER trg_findings_sub_status_settle
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION findings_settle_sub_status();
