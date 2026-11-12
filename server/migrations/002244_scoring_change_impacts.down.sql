UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types - 'scoring_change_applied'
 WHERE enabled_event_types ? 'scoring_change_applied';

DROP TABLE IF EXISTS scoring_change_impacts;
