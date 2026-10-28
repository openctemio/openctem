-- Removes the vuln_asset links and keys. The timeline entry type stays
-- allowed (rows may use it).

DELETE FROM finding_issue_links WHERE rule = 'vuln_asset';
DELETE FROM finding_link_keys WHERE kind = 'vuln_asset';

ALTER TABLE finding_issue_links DROP CONSTRAINT IF EXISTS chk_finding_issue_links_rule;
ALTER TABLE finding_issue_links ADD CONSTRAINT chk_finding_issue_links_rule
    CHECK (rule IN ('sast_overlap', 'secret_value', 'vuln_alias'));

ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_locator;
ALTER TABLE finding_link_keys DROP CONSTRAINT IF EXISTS chk_finding_link_keys_kind;
ALTER TABLE finding_link_keys ADD CONSTRAINT chk_finding_link_keys_kind CHECK (kind IN ('sast_cwe', 'secret_value'));
ALTER TABLE finding_link_keys DROP COLUMN IF EXISTS locator;

-- The facts counted those groups once: rebuild them.
UPDATE dash_fact_status SET rebuild_requested_at = now() WHERE rebuilt_at IS NOT NULL;
