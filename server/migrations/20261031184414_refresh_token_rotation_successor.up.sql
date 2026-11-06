-- Refresh-token rotation grace (docs/architecture/session-refresh.md).
-- A rotated token records the token that replaced it and a hash of the
-- user agent that rotated it. For a short grace window after the rotation the
-- same client presenting the old token again (parallel requests that carried
-- the cookie before the rotation answered) is handed that same successor
-- instead of ending the session. Nothing secret is stored: the successor is
-- re-derived from its row and checked against its stored hash.
-- Nullable columns without a default are a catalog-only change.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS successor_id uuid;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS rotated_fingerprint varchar(64);
