DROP INDEX IF EXISTS idx_bounty_programs_syncable;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_pending;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_sync_error;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_sync_username;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_sync_handle;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_sync_url;
UPDATE bounty_programs SET scope_source = 'paste' WHERE scope_source <> 'paste';
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source CHECK (scope_source IN ('paste'));
ALTER TABLE bounty_programs
    DROP COLUMN IF EXISTS pending_scope_items,
    DROP COLUMN IF EXISTS pending_terms_sha256,
    DROP COLUMN IF EXISTS last_sync_error,
    DROP COLUMN IF EXISTS last_synced_at,
    DROP COLUMN IF EXISTS sync_token_encrypted,
    DROP COLUMN IF EXISTS sync_username,
    DROP COLUMN IF EXISTS sync_handle,
    DROP COLUMN IF EXISTS sync_url;
