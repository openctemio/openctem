-- Reverts 003140: removes the consent the upgrade recorded. Consent given by
-- an administrator (enabled_by = a user id) stays; audit rows stay.
UPDATE tenants
   SET settings = jsonb_set(settings, '{ai}', (settings->'ai') - 'enabled_at' - 'enabled_by'),
       updated_at = now()
 WHERE settings->'ai'->>'enabled_by' = 'upgrade';
