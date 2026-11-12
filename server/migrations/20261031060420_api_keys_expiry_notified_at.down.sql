DROP INDEX IF EXISTS idx_api_keys_expiry_notice;
ALTER TABLE api_keys DROP COLUMN IF EXISTS expiry_notified_at;
