-- API keys must belong to a member: a key with no user carries no data
-- scope and would read every asset of the tenant. Authentication now refuses
-- them; revoke the remaining ones so they show as revoked, not as active keys
-- that silently stopped working.
UPDATE api_keys
   SET status = 'revoked', revoked_at = now(), updated_at = now()
 WHERE user_id IS NULL
   AND revoked_at IS NULL;
