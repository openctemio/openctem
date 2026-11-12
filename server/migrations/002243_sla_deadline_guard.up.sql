-- The SLA tighten-only rule in the database, for every writer
-- (api/docs/architecture/scoring-versions.md, "SLA on a priority change").
--
-- A BEFORE UPDATE trigger keeps an open finding's deadline from moving later
-- or being cleared. Only the paths that start a new SLA clock on purpose may
-- move it later: a regression restart and the end of a risk acceptance mark
-- their own transaction with SET LOCAL openctem.sla_restart = on; the
-- promotion of a branch-only finding is recognised by branch_only going
-- true -> false.
--
-- Live impact: one row trigger on findings; no data is rewritten.

-- Tighten-only guard. When an open finding (before and after the write)
-- would get a later deadline or lose it, the row keeps the deadline it had
-- (and the SLA status for it); the writer's other columns are written. A writer holding an
-- older copy of the row (a full-row update, a recompute that read the row
-- before a tightening) therefore cannot extend it. A closed finding, a first
-- deadline, a marked SLA restart and the promotion of a branch-only finding
-- (promote_branch_only_findings: its SLA clock starts when a counting branch
-- first sees it) are not touched.
CREATE OR REPLACE FUNCTION guard_sla_deadline_tighten_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(current_setting('openctem.sla_restart', true), '') = 'on' THEN
        RETURN NEW;
    END IF;
    NEW.sla_deadline := OLD.sla_deadline;
    -- The status the kept deadline gives (trg_findings_recompute_sla_status
    -- ran first, on the refused one).
    NEW.sla_status := finding_sla_status_for(NEW.status, OLD.sla_deadline, NEW.resolved_at, OLD.sla_status, true);
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION guard_sla_deadline_tighten_only() IS
    'Row trigger: an open finding''s SLA deadline never moves later or is cleared, except in a transaction marked SET LOCAL openctem.sla_restart = on (SLA restart, acceptance expiry).';

DROP TRIGGER IF EXISTS trg_findings_sla_deadline_guard ON findings;
CREATE TRIGGER trg_findings_sla_deadline_guard
    BEFORE UPDATE OF sla_deadline ON findings
    FOR EACH ROW
    WHEN (OLD.sla_deadline IS NOT NULL
          AND (NEW.sla_deadline IS NULL OR NEW.sla_deadline > OLD.sla_deadline)
          AND is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status)
          AND NOT (OLD.branch_only AND NOT NEW.branch_only))
    EXECUTE FUNCTION guard_sla_deadline_tighten_only();
