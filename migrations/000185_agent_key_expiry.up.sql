-- Agent credential expiry (RFC-014 Phase 1b).
-- Nullable: NULL = the key never expires (every pre-existing row), so this is a
-- pure additive change with no behavior shift until an operator opts in via a
-- configured key TTL and agents renew. Enforced in AuthenticateByAPIKey.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS key_expires_at TIMESTAMPTZ;

-- Partial index supports a future "expiring soon" sweep / reporting without
-- bloating the common NULL case.
CREATE INDEX IF NOT EXISTS idx_agents_key_expires_at ON agents(key_expires_at) WHERE key_expires_at IS NOT NULL;
