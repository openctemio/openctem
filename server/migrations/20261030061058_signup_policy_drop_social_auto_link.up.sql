-- Automatic linking of a social sign-in to an existing account is removed:
-- a collision always needs the typed proof (docs/architecture/social-login-linking.md).
-- The sign-up policy no longer has a "social_auto_link" value; drop any that
-- an earlier build stored. The rest of the policy is kept.
UPDATE platform_settings
   SET value = value - 'social_auto_link',
       version = version + 1,
       updated_at = now()
 WHERE key = 'signup_policy'
   AND value ? 'social_auto_link';
