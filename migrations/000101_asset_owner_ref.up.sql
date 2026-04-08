-- Add owner_ref: raw owner text from external sources (email, username, team name, etc.)
-- Used when the owner hasn't registered in the system yet.
-- Auto-matched to owner_id (FK users) when possible.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_ref VARCHAR(500);

CREATE INDEX IF NOT EXISTS idx_assets_owner_ref
    ON assets(tenant_id, owner_ref)
    WHERE owner_ref IS NOT NULL;
