-- Same-issue links between the http and https views of one page
-- (docs/architecture/deduplication.md, "Same issue across tools"): the same
-- DAST check (rule and method) at the same host, path and parameter names on
-- the same asset, reached over http and over https on the default ports. Each
-- scheme stays its own finding (another origin, port and transport); the link
-- shows them as one issue, counted once, with no second notification.
--
-- finding_link_keys gains the kind dast_point (hash of asset, rule, method,
-- host and path, parameter names) whose locator is the scheme.
-- finding_issue_links gains the rule dast_scheme. Constraint changes only: the
-- keys are written by ingest and by refingerprint -links.

ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_kind;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_kind
    CHECK (kind IN ('sast_cwe', 'secret_value', 'vuln_asset', 'dast_point'));
ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_locator;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_locator
    CHECK (locator IS NULL OR (kind IN ('vuln_asset', 'dast_point') AND locator <> ''));
COMMENT ON COLUMN finding_link_keys.locator IS
    'vuln_asset: where on the asset the finding sits, "port/proto" or "host" (linked when equal or one is host). dast_point: the URL scheme (linked when the schemes differ).';

ALTER TABLE finding_issue_links DROP CONSTRAINT IF EXISTS chk_finding_issue_links_rule;
ALTER TABLE finding_issue_links ADD CONSTRAINT chk_finding_issue_links_rule
    CHECK (rule IN ('sast_overlap', 'secret_value', 'vuln_alias', 'vuln_asset', 'dast_scheme'));
