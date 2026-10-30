-- Automatic linking of social sign-in to existing accounts is off by default
-- (docs/architecture/social-login-linking.md). The console sent the old
-- default (on) back with every save of the sign-up policy, so a stored
-- "social_auto_link" does not show an operator's choice: drop it, so every
-- deployment starts with the new default. An operator who wants it turns it
-- on again in Console > Settings > Sign-up (audited).
UPDATE platform_settings
   SET value = value - 'social_auto_link',
       version = version + 1,
       updated_at = now()
 WHERE key = 'signup_policy'
   AND value ? 'social_auto_link';
