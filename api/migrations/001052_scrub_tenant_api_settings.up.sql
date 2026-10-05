-- The legacy organization API/webhook settings (settings.api: api_key_enabled,
-- webhook_url, webhook_secret, webhook_events) were never read by anything,
-- and webhook_secret sat in plaintext outside the encryption-key rotation.
-- The PATCH /settings/api endpoint is removed; this scrubs the stored key.
UPDATE tenants SET settings = settings - 'api' WHERE settings ? 'api';
