-- A false positive decided by one person (single_person, or the sole
-- member's self_approved) gets a review flag when the finding later becomes
-- material: its severity rises, it is added to the known exploited list
-- (KEV), or new evidence is attached. The decision stands; the flag
-- (finding_decision_reviews, reason material_change_single_person) and a
-- decision_review timeline entry ask a person with the approve permission to
-- look again. Triggers catch every write path (scans, enrichment, people).
--
-- Live impact: two triggers. Creating them takes a short lock on findings and
-- finding_evidence and scans nothing; the findings trigger fires only when a
-- false positive's severity or KEV flag changes (WHEN clause).

-- Two new review reasons: material_change_single_person (above) and
-- second_look_sample (a random share of single-person false positives the
-- organization asks a second person to look at). NOT VALID here, validated by
-- the next migration.
ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match', 'material_change_single_person', 'second_look_sample')) NOT VALID;

CREATE OR REPLACE FUNCTION finding_severity_rank(sev text) RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE lower(sev) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                           WHEN 'low' THEN 1 ELSE 0 END
$$;

CREATE OR REPLACE FUNCTION flag_single_person_fp_review(p_tenant uuid, p_finding uuid, p_change text, p_evidence jsonb)
    RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- Only a false positive whose latest approved decision was one person's.
    IF NOT EXISTS (
        SELECT 1 FROM (
            SELECT a.single_person, a.self_approved
            FROM finding_status_approvals a
            WHERE a.tenant_id = p_tenant AND a.finding_id = p_finding
              AND a.requested_status = 'false_positive' AND a.status = 'approved'
            ORDER BY a.approved_at DESC NULLS LAST, a.created_at DESC
            LIMIT 1) last
        WHERE last.single_person OR last.self_approved) THEN
        RETURN;
    END IF;
    WITH flag AS (
        INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
        VALUES (p_tenant, p_finding, 'false_positive', 'material_change_single_person',
                p_evidence || jsonb_build_object('change', p_change))
        ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING
        RETURNING 1
    )
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
    SELECT p_tenant, p_finding, 'decision_review', 'system', 'system: material_change_single_person',
           jsonb_build_object('decision_status', 'false_positive', 'reason', 'material_change_single_person',
                              'evidence', p_evidence || jsonb_build_object('change', p_change)),
           'auto',
           'One person decided this false positive and the finding changed (' || p_change || '); it stands until a person reviews it'
    FROM flag;
END $$;

CREATE OR REPLACE FUNCTION trg_findings_single_person_fp_review() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF finding_severity_rank(NEW.severity) > finding_severity_rank(OLD.severity) THEN
        PERFORM flag_single_person_fp_review(NEW.tenant_id, NEW.id, 'severity_raised',
            jsonb_build_object('severity_before', OLD.severity, 'severity_after', NEW.severity));
    END IF;
    IF COALESCE(NEW.is_in_kev, false) AND NOT COALESCE(OLD.is_in_kev, false) THEN
        PERFORM flag_single_person_fp_review(NEW.tenant_id, NEW.id, 'kev_added', '{}'::jsonb);
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_findings_single_person_fp_review ON findings;
CREATE TRIGGER trg_findings_single_person_fp_review
    AFTER UPDATE OF severity, is_in_kev ON findings
    FOR EACH ROW
    WHEN (NEW.status = 'false_positive'
          AND (NEW.severity IS DISTINCT FROM OLD.severity OR NEW.is_in_kev IS DISTINCT FROM OLD.is_in_kev))
    EXECUTE FUNCTION trg_findings_single_person_fp_review();

CREATE OR REPLACE FUNCTION trg_finding_evidence_single_person_fp_review() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM findings f WHERE f.tenant_id = NEW.tenant_id AND f.id = NEW.finding_id
               AND f.status = 'false_positive') THEN
        PERFORM flag_single_person_fp_review(NEW.tenant_id, NEW.finding_id, 'new_evidence',
            jsonb_build_object('evidence_id', NEW.id, 'kind', NEW.kind));
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_finding_evidence_single_person_fp_review ON finding_evidence;
CREATE TRIGGER trg_finding_evidence_single_person_fp_review
    AFTER INSERT ON finding_evidence
    FOR EACH ROW EXECUTE FUNCTION trg_finding_evidence_single_person_fp_review();

COMMENT ON FUNCTION finding_severity_rank(text) IS 'Severity order for comparisons: critical 4, high 3, medium 2, low 1, anything else 0';
COMMENT ON FUNCTION flag_single_person_fp_review(uuid, uuid, text, jsonb) IS
    'Raises the material_change_single_person review flag (and a timeline entry) on a false positive whose latest approved decision was one person''s';
