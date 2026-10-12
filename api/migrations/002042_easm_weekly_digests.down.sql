UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types - 'attack_surface_digest'
 WHERE enabled_event_types ? 'attack_surface_digest';

DROP TABLE IF EXISTS easm_weekly_digests;
