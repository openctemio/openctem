-- When the "your API key expires soon" notice was sent (NULL: not yet).
-- Nullable, no default: adding it rewrites nothing and takes no long lock.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expiry_notified_at TIMESTAMPTZ;

-- The expiry sweep reads active keys that expire soon and were not told.
CREATE INDEX IF NOT EXISTS idx_api_keys_expiry_notice
    ON api_keys (expires_at)
    WHERE status = 'active' AND expiry_notified_at IS NULL AND expires_at IS NOT NULL;
