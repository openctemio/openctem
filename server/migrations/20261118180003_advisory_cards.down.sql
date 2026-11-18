DELETE FROM vuln_events WHERE kind IN ('card_published', 'card_updated', 'card_withdrawn');
ALTER TABLE vuln_events DROP CONSTRAINT IF EXISTS vuln_events_kind_check;
ALTER TABLE vuln_events ADD CONSTRAINT vuln_events_kind_check CHECK (kind IN ('published', 'ranges_added', 'ranges_widened',
    'severity_up', 'kev_added', 'epss_crossed', 'rejected'));

DROP TABLE IF EXISTS advisory_card_products;
DROP TABLE IF EXISTS advisory_card_vulns;
DROP TABLE IF EXISTS advisory_card_revisions;
DROP TABLE IF EXISTS advisory_cards;
