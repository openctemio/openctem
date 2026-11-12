-- sla_kev_deadline_cap (up)
-- Known exploited deadline cap (api/docs/architecture/scoring-versions.md,
-- "Known exploited deadline cap").
--
-- sla_policies.kev_cap_days: an open finding whose CVE is in CISA KEV is due
-- at most this many days after the platform first sees it as known exploited
-- (0 = off). The applier takes min(deadline, first KEV sighting + cap), so
-- the cap only ever tightens a deadline.
-- findings.sla_kev_capped: the stored deadline came from that cap (the
-- finding SLA explains "shortened because it is in CISA KEV").
--
-- The SLA timeline entry names the cap as its reason, and the tighten-only
-- guard keeps the flag with the deadline it keeps.
--
-- Live impact: two ADD COLUMN with a constant default (catalog-only, no table
-- rewrite); the CHECK scans sla_policies (a few rows per tenant); two
-- trigger functions are replaced. No finding row is written.

ALTER TABLE sla_policies
    ADD COLUMN IF NOT EXISTS kev_cap_days integer NOT NULL DEFAULT 14;
ALTER TABLE sla_policies
    ADD CONSTRAINT chk_sla_policies_kev_cap_days CHECK (kev_cap_days BETWEEN 0 AND 365);
COMMENT ON COLUMN sla_policies.kev_cap_days IS
    'Known exploited (KEV) deadline cap in days: a KEV finding is due at most this long after it is first seen as KEV. 0 = off.';

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_kev_capped boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN findings.sla_kev_capped IS
    'The SLA deadline was shortened by the policy''s known exploited (KEV) deadline cap.';

-- The timeline entry of a tightening names the KEV cap when it set the flag.
CREATE OR REPLACE FUNCTION record_sla_deadline_tightened() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_reason text;
BEGIN
    v_reason := CASE
        WHEN NEW.sla_kev_capped AND NOT OLD.sla_kev_capped THEN 'kev_cap'
        -- P0 sorts before P3: a lower class string is a higher priority.
        WHEN NEW.priority_class IS NOT NULL
             AND (OLD.priority_class IS NULL OR NEW.priority_class < OLD.priority_class) THEN 'priority_raised'
        ELSE 'sla_policy_changed'
    END;
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source)
    VALUES (
        NEW.tenant_id, NEW.id, 'sla_deadline_tightened', 'system', 'system: SLA', jsonb_build_object(
            'previous_sla_deadline', to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'sla_deadline', to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'previous_priority_class', OLD.priority_class,
            'priority_class', NEW.priority_class,
            'reason', v_reason,
            'content', CASE
                WHEN v_reason = 'kev_cap' THEN format('SLA deadline moved earlier, from %s to %s, because the vulnerability is in CISA KEV (known exploited)',
                    to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'))
                WHEN v_reason = 'priority_raised' THEN format('SLA deadline moved earlier, from %s to %s, because the priority rose from %s to %s',
                    to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    COALESCE(OLD.priority_class, 'none'), COALESCE(NEW.priority_class, 'none'))
                ELSE format('SLA deadline moved earlier, from %s to %s, because the SLA policy changed',
                    to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'))
            END),
        'auto');
    RETURN NULL;
END;
$$;

-- The guard keeps the old deadline; the KEV flag stays with it.
CREATE OR REPLACE FUNCTION guard_sla_deadline_tighten_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(current_setting('openctem.sla_restart', true), '') = 'on' THEN
        RETURN NEW;
    END IF;
    NEW.sla_deadline := OLD.sla_deadline;
    NEW.sla_kev_capped := OLD.sla_kev_capped;
    -- The status the kept deadline gives (trg_findings_recompute_sla_status
    -- ran first, on the refused one).
    NEW.sla_status := finding_sla_status_for(NEW.status, OLD.sla_deadline, NEW.resolved_at, OLD.sla_status, true);
    RETURN NEW;
END;
$$;
