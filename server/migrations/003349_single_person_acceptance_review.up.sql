-- A risk acceptance one person decided (single_person under the
-- organization's risk acceptance level, or the sole member's self_approved)
-- gets the same review flag as a false positive one person decided when the
-- finding later becomes material: its severity rises, it is added to the
-- known exploited list (KEV), or new evidence is attached. The decision
-- stands; the flag (finding_decision_reviews, reason
-- material_change_single_person, decision_status accepted) and a
-- decision_review timeline entry ask a person with the approve permission to
-- look again. The material-change controller still ends an acceptance whose
-- tier now needs a second person. Raising an approval level calls the same
-- function (change level_raised) for the standing decisions one person made
-- that the new level gives to a second person. Design: api/docs/rfcs/RFC-111-approval-policy.md.
--
-- Live impact: replaces three functions and one trigger on findings (a short
-- lock, nothing scanned); one partial index on finding_status_approvals (a
-- small table) for the approvals digest's "decided by one person" list.

CREATE OR REPLACE FUNCTION flag_single_person_decision_review(p_tenant uuid, p_finding uuid, p_status text,
                                                              p_change text, p_evidence jsonb)
    RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_status NOT IN ('false_positive', 'accepted') THEN
        RETURN;
    END IF;
    -- Only when the latest approved decision of that status was one person's.
    IF NOT EXISTS (
        SELECT 1 FROM (
            SELECT a.single_person, a.self_approved
            FROM finding_status_approvals a
            WHERE a.tenant_id = p_tenant AND a.finding_id = p_finding
              AND a.requested_status = p_status AND a.status = 'approved'
            ORDER BY a.approved_at DESC NULLS LAST, a.created_at DESC
            LIMIT 1) last
        WHERE last.single_person OR last.self_approved) THEN
        RETURN;
    END IF;
    WITH flag AS (
        INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
        VALUES (p_tenant, p_finding, p_status, 'material_change_single_person',
                p_evidence || jsonb_build_object('change', p_change))
        ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING
        RETURNING 1
    )
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
    SELECT p_tenant, p_finding, 'decision_review', 'system', 'system: material_change_single_person',
           jsonb_build_object('decision_status', p_status, 'reason', 'material_change_single_person',
                              'evidence', p_evidence || jsonb_build_object('change', p_change)),
           'auto',
           CASE WHEN p_change = 'level_raised'
               THEN 'One person decided this ' || CASE p_status WHEN 'accepted' THEN 'risk acceptance' ELSE 'false positive' END
                    || ' and the organization has since raised its approval level; it stands until a person reviews it'
               ELSE 'One person decided this ' || CASE p_status WHEN 'accepted' THEN 'risk acceptance' ELSE 'false positive' END
                    || ' and the finding changed (' || p_change || '); it stands until a person reviews it'
           END
    FROM flag;
END $$;

CREATE OR REPLACE FUNCTION trg_findings_single_person_fp_review() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF finding_severity_rank(NEW.severity) > finding_severity_rank(OLD.severity) THEN
        PERFORM flag_single_person_decision_review(NEW.tenant_id, NEW.id, NEW.status, 'severity_raised',
            jsonb_build_object('severity_before', OLD.severity, 'severity_after', NEW.severity));
    END IF;
    IF COALESCE(NEW.is_in_kev, false) AND NOT COALESCE(OLD.is_in_kev, false) THEN
        PERFORM flag_single_person_decision_review(NEW.tenant_id, NEW.id, NEW.status, 'kev_added', '{}'::jsonb);
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_findings_single_person_fp_review ON findings;
CREATE TRIGGER trg_findings_single_person_fp_review
    AFTER UPDATE OF severity, is_in_kev ON findings
    FOR EACH ROW
    WHEN (NEW.status IN ('false_positive', 'accepted')
          AND (NEW.severity IS DISTINCT FROM OLD.severity OR NEW.is_in_kev IS DISTINCT FROM OLD.is_in_kev))
    EXECUTE FUNCTION trg_findings_single_person_fp_review();

CREATE OR REPLACE FUNCTION trg_finding_evidence_single_person_fp_review() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    v_status text;
BEGIN
    SELECT f.status INTO v_status FROM findings f WHERE f.tenant_id = NEW.tenant_id AND f.id = NEW.finding_id;
    IF v_status IN ('false_positive', 'accepted') THEN
        PERFORM flag_single_person_decision_review(NEW.tenant_id, NEW.finding_id, v_status, 'new_evidence',
            jsonb_build_object('evidence_id', NEW.id, 'kind', NEW.kind));
    END IF;
    RETURN NULL;
END $$;

DROP FUNCTION IF EXISTS flag_single_person_fp_review(uuid, uuid, text, jsonb);

CREATE INDEX IF NOT EXISTS idx_finding_status_approvals_decided_alone
    ON finding_status_approvals (approved_at)
    WHERE status = 'approved' AND (single_person OR self_approved);

COMMENT ON FUNCTION flag_single_person_decision_review(uuid, uuid, text, text, jsonb) IS
    'Raises the material_change_single_person review flag (and a timeline entry) on a false positive or accepted risk whose latest approved decision was one person''s';
COMMENT ON COLUMN finding_status_approvals.single_person IS
    'Decided by one person under the organization''s false-positive or risk acceptance approval level (no second approver)';
