-- Why something is out of scope (research/320, RFC-054 §20). Every kind
-- stops scanning the same way; the kind decides what else happens:
--   do_not_scan  the organization's own, must not be scanned; findings stay open
--   not_ours     someone else's
--   retired      gone for good
-- A permanent exclusion of a closing kind (not_ours, retired) that is in
-- effect closes the open findings of the assets it matches as resolved,
-- closure reason out_of_scope (never counted as fixed); taking it out of
-- effect reopens them (the scope effects reconciler, scope/effects.go).
--
-- Existing exclusions become do_not_scan, the meaning they had: deploying
-- this closes nothing. Adding a column with a constant default is a catalog
-- change (no table rewrite).

ALTER TABLE scope_exclusions
    ADD COLUMN kind varchar(16) NOT NULL DEFAULT 'do_not_scan';

ALTER TABLE scope_exclusions
    ADD CONSTRAINT chk_scope_exclusions_kind CHECK (kind IN ('do_not_scan', 'not_ours', 'retired'));

COMMENT ON COLUMN scope_exclusions.kind IS
    'Why it is out of scope: do_not_scan (findings stay open), not_ours or retired (a permanent one in effect closes the findings of what it matches as out_of_scope)';

-- A finding closed because its asset went out of scope: resolved with the
-- closure reason out_of_scope (closure.go). Same rule table as before plus
-- that one reason; the DB test pins it to the Go tables.
CREATE OR REPLACE FUNCTION finding_closure_valid(p_status text, p_reason text, p_verification text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT COALESCE(CASE
        WHEN p_status IN ('resolved', 'false_positive', 'accepted', 'duplicate') THEN
            p_reason IS NOT NULL
            AND (p_reason = 'unknown' OR CASE p_status
                WHEN 'resolved' THEN p_reason IN ('fixed', 'mitigated', 'obsolete_asset', 'obsolete_source', 'obsolete_rule',
                    'out_of_scope')
                WHEN 'false_positive' THEN p_reason IN ('component_not_present', 'vulnerable_code_not_present',
                    'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
                    'inline_mitigations_already_exist', 'detection_error', 'test_or_example_code')
                WHEN 'accepted' THEN p_reason IN ('risk_accepted', 'compensating_control', 'wont_fix', 'no_fix_available')
                ELSE p_reason IN ('duplicate', 'correlated')
            END)
            AND CASE p_status
                WHEN 'resolved' THEN p_verification IN ('covered_scan', 'retest', 'source_reported', 'vex_statement',
                    'security_review', 'attested', 'none', 'unknown')
                WHEN 'false_positive' THEN p_verification IS NULL
                    OR p_verification IN ('source_reported', 'vex_statement', 'security_review', 'unknown')
                ELSE p_verification IS NULL
            END
        ELSE p_reason IS NULL AND p_verification IS NULL
    END, false)
$$;

-- Cut-over: when out-of-scope decisions started to close findings. A "not
-- ours" decision (a rejected attribution) or a closing exclusion made before
-- this moment keeps what it always did (the asset is not scanned) and closes
-- nothing; only decisions made at or after it do. Without this, deploying
-- would close the open findings of every asset already marked not ours. One
-- row for the platform; a missing row closes nothing (fail closed).
CREATE TABLE scope_effects_cutover (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    effective_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO scope_effects_cutover (singleton) VALUES (true);
COMMENT ON TABLE scope_effects_cutover IS
    'When out-of-scope decisions started closing findings: older not-ours decisions and closing exclusions only stop scanning';
