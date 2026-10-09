-- The retired modules switched nothing and their overrides are gone; they
-- are not recreated. Only the core flag is reverted.
UPDATE modules SET is_core = FALSE
 WHERE id IN ('sensors', 'groups', 'api_keys', 'notification_settings', 'integrations',
              'integrations.notifications');
