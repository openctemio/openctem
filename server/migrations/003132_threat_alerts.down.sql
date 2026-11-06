DELETE FROM event_types WHERE id IN ('emerging_threat', 'emerging_threat_digest');
UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types - 'emerging_threat' - 'emerging_threat_digest'
 WHERE enabled_event_types ? 'emerging_threat' OR enabled_event_types ? 'emerging_threat_digest';

DROP TABLE IF EXISTS threat_alert_tenant_state;
DROP TABLE IF EXISTS threat_alert_queue;
DROP TABLE IF EXISTS threat_alert_assets;
DROP TABLE IF EXISTS threat_alerts;
