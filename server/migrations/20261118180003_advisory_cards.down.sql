-- Alerts the cards changed: the per-vulnerability alerts resolved as grouped
-- into a card reopen (they would stay hidden otherwise), the alerts keyed by
-- a card are resolved and their queue rows removed.
UPDATE threat_alerts SET state = 'new', state_reason = '', resolved_at = NULL, state_changed_at = now(),
    digest_pending = true, updated_at = now()
WHERE state = 'resolved' AND state_reason = 'grouped_into_card';
UPDATE threat_alerts SET state = 'resolved', state_reason = 'card_withdrawn', resolved_at = now(), state_changed_at = now(),
    updated_at = now()
WHERE vuln_id ~ '^OCA-' AND state <> 'resolved';
DELETE FROM threat_alert_queue WHERE vuln_id ~ '^OCA-';
DROP INDEX IF EXISTS idx_threat_alerts_grouped_into_card;
ALTER TABLE threat_alerts DROP COLUMN IF EXISTS grouped_into_card;

DELETE FROM vuln_events WHERE kind IN ('card_published', 'card_updated', 'card_withdrawn');
ALTER TABLE vuln_events DROP CONSTRAINT IF EXISTS vuln_events_kind_check;
ALTER TABLE vuln_events ADD CONSTRAINT vuln_events_kind_check CHECK (kind IN ('published', 'ranges_added', 'ranges_widened',
    'severity_up', 'kev_added', 'epss_crossed', 'rejected'));

DROP TABLE IF EXISTS advisory_card_stream;
DROP TABLE IF EXISTS advisory_card_products;
DROP TABLE IF EXISTS advisory_card_vulns;
DROP TABLE IF EXISTS advisory_card_revisions;
DROP TABLE IF EXISTS advisory_cards;
