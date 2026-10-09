-- Program sync (RFC-065 §14): a program keeps its scope in sync with the
-- researcher scope API of the platform that runs it, or with a scope file
-- the program publishes. Narrowing applies at once; widening waits as
-- pending terms until a member accepts them. Columns are nullable or have
-- defaults (no rewrite); bounty_programs is small.

ALTER TABLE bounty_programs
    ADD COLUMN IF NOT EXISTS sync_url              text,
    ADD COLUMN IF NOT EXISTS sync_handle           text,
    ADD COLUMN IF NOT EXISTS sync_username         text,
    ADD COLUMN IF NOT EXISTS sync_token_encrypted  text,
    ADD COLUMN IF NOT EXISTS last_synced_at        timestamptz,
    ADD COLUMN IF NOT EXISTS last_sync_error       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pending_terms_sha256  text,
    ADD COLUMN IF NOT EXISTS pending_scope_items   jsonb;

-- expand-contract-ok: the constraint only widens; the old api writes 'paste' only
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'program_api', 'program_file'));
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_sync_url
    CHECK (sync_url IS NULL OR (sync_url LIKE 'https://%' AND length(sync_url) <= 500));
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_sync_handle
    CHECK (sync_handle IS NULL OR sync_handle ~ '^[A-Za-z0-9_.-]{1,100}$');
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_sync_username
    CHECK (sync_username IS NULL OR length(sync_username) BETWEEN 1 AND 100);
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_sync_error
    CHECK (length(last_sync_error) <= 500);
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_pending
    CHECK ((pending_terms_sha256 IS NULL) = (pending_scope_items IS NULL)
           AND (pending_terms_sha256 IS NULL OR pending_terms_sha256 ~ '^[0-9a-f]{64}$'));

CREATE INDEX IF NOT EXISTS idx_bounty_programs_syncable ON bounty_programs (last_synced_at)
    WHERE scope_source <> 'paste' AND status = 'active';

COMMENT ON COLUMN bounty_programs.sync_token_encrypted IS 'The researcher''s API token for program_api sync, encrypted with APP_ENCRYPTION_KEY; never returned';
COMMENT ON COLUMN bounty_programs.pending_terms_sha256 IS 'Terms a sync found that widen the scope; nothing is added until a member accepts them';
