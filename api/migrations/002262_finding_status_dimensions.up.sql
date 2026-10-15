-- validated_fixed and not_observed stop being statuses (pkg/domain/
-- vulnerability/observation.go): whether the scanner still reports a finding
-- is findings.observation_state (present / stale), and whether a re-check
-- reproduces it is findings.validation_outcome (reproducible /
-- not_reproducible). The status keeps the next human action.
--
-- A finding in a retired status returns to the status it had before (the
-- latest timeline entry that moved it there), else confirmed, keeps the
-- meaning in its dimension, and gets a timeline entry. Stored filter
-- documents (saved views, remediation campaigns) that name a retired status
-- are rewritten to the dimension. The status CHECK is added NOT VALID here
-- and validated in the next migration.

ALTER TABLE findings ADD COLUMN observation_state varchar(16) NOT NULL DEFAULT 'present';
ALTER TABLE findings ADD CONSTRAINT chk_findings_observation_state
    CHECK (observation_state IN ('present', 'stale')) NOT VALID;
COMMENT ON COLUMN findings.observation_state IS
    'present, or stale: no longer reported and no coverage proof (observation.go); never a status';

-- Every finding this transaction moves gets its timeline entry
-- (record_finding_transition reads this setting).
SELECT set_config('openctem.transition', '{"source": "migration", "reason": "status_retired", "actor_type": "system", "actor_name": "system: finding status model", "message": "This status is now a field beside the status: observation stale, or validation not reproducible"}', true);

WITH moved AS (
    SELECT f.id, f.status AS retired,
           COALESCE((
               SELECT a.changes->>'old_status'
               FROM finding_activities a
               WHERE a.tenant_id = f.tenant_id AND a.finding_id = f.id
                 AND a.changes->>'new_status' = f.status
                 AND a.changes->>'old_status' IN ('new', 'confirmed', 'in_progress', 'fix_applied')
               ORDER BY a.created_at DESC
               LIMIT 1), 'confirmed') AS back_to
    FROM findings f
    WHERE f.status IN ('validated_fixed', 'not_observed')
)
UPDATE findings f SET
    status = m.back_to,
    observation_state = CASE WHEN m.retired = 'not_observed' THEN 'stale' ELSE f.observation_state END,
    validation_outcome = CASE WHEN m.retired = 'validated_fixed' THEN 'not_reproducible' ELSE f.validation_outcome END,
    -- the retired statuses carried machine notes (branch_expired, source_stale)
    resolution = NULL,
    updated_at = NOW()
FROM moved m
WHERE f.id = m.id;

SELECT set_config('openctem.transition', '', true);

ALTER TABLE findings DROP CONSTRAINT chk_findings_status;
ALTER TABLE findings ADD CONSTRAINT chk_findings_status CHECK (status IN (
    'new', 'confirmed', 'in_progress', 'fix_applied', 'resolved', 'false_positive', 'accepted', 'duplicate',
    'draft', 'in_review')) NOT VALID;

CREATE OR REPLACE FUNCTION is_open_finding_status(p_status text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE PARALLEL SAFE
AS $$
    SELECT p_status IN ('new', 'confirmed', 'in_progress', 'fix_applied')
$$;

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Closed dispositions (false_positive, accepted, duplicate) are triage
    -- corrections, not a fix that failed.
    IF OLD.status = 'resolved'
       AND NEW.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')
       AND COALESCE(current_setting('openctem.person_move', true), '') <> 'on'
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

-- Stored filter documents (RFC-048): a status leaf naming a retired status
-- becomes the dimension. "status in (x, not_observed)" becomes
-- "status in (x) OR observation = stale"; "status not in (..., not_observed)"
-- drops the value (no finding has it). In the flat shorthand form a list that
-- named only one retired status becomes the dimension; otherwise the retired
-- values are dropped from the list.
CREATE FUNCTION retire_finding_status_filter(doc jsonb) RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    dims  constant jsonb := '{"not_observed": {"field": "observation", "op": "eq", "value": "stale"},
                               "validated_fixed": {"field": "validation", "op": "eq", "value": "not_reproducible"}}';
    vals  jsonb;
    kept  jsonb;
    gone  text[];
    alts  jsonb;
    out   jsonb;
    k     text;
    v     jsonb;
BEGIN
    IF doc IS NULL THEN
        RETURN NULL;
    END IF;
    IF jsonb_typeof(doc) = 'array' THEN
        SELECT COALESCE(jsonb_agg(retire_finding_status_filter(e)), '[]'::jsonb) INTO out FROM jsonb_array_elements(doc) e;
        RETURN out;
    END IF;
    IF jsonb_typeof(doc) <> 'object' THEN
        RETURN doc;
    END IF;

    -- A node leaf on the status.
    IF doc ? 'field' AND doc->>'field' IN ('status', 'statuses') THEN
        vals := CASE WHEN jsonb_typeof(doc->'value') = 'array' THEN doc->'value' ELSE jsonb_build_array(doc->'value') END;
        SELECT COALESCE(jsonb_agg(e), '[]'::jsonb) INTO kept FROM jsonb_array_elements(vals) e
            WHERE e #>> '{}' NOT IN ('not_observed', 'validated_fixed');
        SELECT array_agg(e #>> '{}') INTO gone FROM jsonb_array_elements(vals) e
            WHERE e #>> '{}' IN ('not_observed', 'validated_fixed');
        IF gone IS NULL THEN
            RETURN doc;
        END IF;
        IF doc->>'op' IN ('not_in', 'ne') THEN
            IF jsonb_array_length(kept) = 0 THEN
                RETURN '{"field": "observation", "op": "in", "value": ["present", "stale"]}'::jsonb;
            END IF;
            RETURN jsonb_build_object('field', 'status', 'op', 'not_in', 'value', kept);
        END IF;
        alts := '[]'::jsonb;
        IF jsonb_array_length(kept) > 0 THEN
            alts := alts || jsonb_build_array(jsonb_build_object('field', 'status', 'op', 'in', 'value', kept));
        END IF;
        SELECT alts || COALESCE(jsonb_agg(DISTINCT dims->g), '[]'::jsonb) INTO alts FROM unnest(gone) g;
        IF jsonb_array_length(alts) = 1 THEN
            RETURN alts->0;
        END IF;
        RETURN jsonb_build_object('any', alts);
    END IF;

    out := '{}'::jsonb;
    FOR k, v IN SELECT * FROM jsonb_each(doc) LOOP
        IF k IN ('status', 'status_not') AND jsonb_typeof(v) IN ('array', 'string') THEN
            -- the flat shorthand form
            vals := CASE WHEN jsonb_typeof(v) = 'array' THEN v ELSE jsonb_build_array(v) END;
            SELECT COALESCE(jsonb_agg(e), '[]'::jsonb) INTO kept FROM jsonb_array_elements(vals) e
                WHERE e #>> '{}' NOT IN ('not_observed', 'validated_fixed');
            SELECT array_agg(e #>> '{}') INTO gone FROM jsonb_array_elements(vals) e
                WHERE e #>> '{}' IN ('not_observed', 'validated_fixed');
            IF gone IS NULL THEN
                out := out || jsonb_build_object(k, v);
            ELSIF k = 'status' AND jsonb_array_length(kept) = 0 AND array_length(gone, 1) = 1 THEN
                out := out || jsonb_build_object(dims->gone[1]->>'field', dims->gone[1]->'value');
            ELSIF jsonb_array_length(kept) > 0 THEN
                out := out || jsonb_build_object(k, kept);
            END IF;
        ELSE
            out := out || jsonb_build_object(k, retire_finding_status_filter(v));
        END IF;
    END LOOP;
    RETURN out;
END;
$$;

UPDATE saved_views SET filter = retire_finding_status_filter(filter), updated_at = NOW()
WHERE filter::text ~ '"(not_observed|validated_fixed)"';
UPDATE remediation_campaigns SET finding_filter = retire_finding_status_filter(finding_filter)
WHERE finding_filter::text ~ '"(not_observed|validated_fixed)"';

DROP FUNCTION retire_finding_status_filter(jsonb);
