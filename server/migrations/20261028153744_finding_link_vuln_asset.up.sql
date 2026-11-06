-- Same-issue links across techniques on one asset (docs/architecture/deduplication.md,
-- "Same issue across tools"): the same CVE on the same asset, found by
-- different techniques (a version match, an active template check, a network
-- scanner import), is linked as the same issue. Nothing moves on either
-- finding.
--
-- finding_link_keys gains the kind vuln_asset (hash of asset and canonical CVE)
-- and a locator ("443/tcp", or "host") that the planner compares so findings
-- on different ports are not linked. finding_issue_links gains the rule
-- vuln_asset. The timeline gains detected_by_another_source.

ALTER TABLE finding_link_keys ADD COLUMN IF NOT EXISTS locator varchar(16);

ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_kind;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_kind
    CHECK (kind IN ('sast_cwe', 'secret_value', 'vuln_asset'));
ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_locator;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_locator
    CHECK (locator IS NULL OR (kind = 'vuln_asset' AND locator <> ''));
COMMENT ON COLUMN finding_link_keys.locator IS
    'vuln_asset only: where on the asset the finding sits, "port/proto" or "host". Two findings link only when the locators agree (equal, or one is host).';

ALTER TABLE finding_issue_links DROP CONSTRAINT IF EXISTS chk_finding_issue_links_rule;
ALTER TABLE finding_issue_links ADD CONSTRAINT chk_finding_issue_links_rule
    CHECK (rule IN ('sast_overlap', 'secret_value', 'vuln_alias', 'vuln_asset'));

DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['detected_by_another_source'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT vals @> added THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM (SELECT DISTINCT unnest(vals || added) AS v) u));
    END IF;
END;
$$;
