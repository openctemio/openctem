-- Removes the dast_scheme links and dast_point keys.

DELETE FROM finding_issue_links WHERE rule = 'dast_scheme';
DELETE FROM finding_link_keys WHERE kind = 'dast_point';

ALTER TABLE finding_issue_links DROP CONSTRAINT IF EXISTS chk_finding_issue_links_rule;
ALTER TABLE finding_issue_links ADD CONSTRAINT chk_finding_issue_links_rule
    CHECK (rule IN ('sast_overlap', 'secret_value', 'vuln_alias', 'vuln_asset'));

ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_locator;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_locator
    CHECK (locator IS NULL OR (kind = 'vuln_asset' AND locator <> ''));
ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_kind;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_kind
    CHECK (kind IN ('sast_cwe', 'secret_value', 'vuln_asset'));

-- The facts counted those groups once: rebuild them.
UPDATE dash_fact_status SET rebuild_requested_at = now() WHERE rebuilt_at IS NOT NULL;
