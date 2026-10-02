-- Restore the pre-parity catalog.
--
-- Rolling back re-offers 'import' in the Add Finding dialog, which the
-- findings.source CHECK constraint rejects — that is the bug this migration
-- fixed, restored faithfully rather than silently improved on.

UPDATE finding_sources
SET is_active = TRUE,
    description = 'Imported from external sources',
    updated_at = NOW()
WHERE code = 'import';

DELETE FROM finding_sources
WHERE code IN ('easm', 'cspm', 'external', 'threat_intel', 'vendor',
               'rasp', 'waf', 'siem', 'bug_bounty', 'red_team', 'sca_tool');

DELETE FROM finding_source_categories
WHERE code IN ('attack_surface', 'cloud');
