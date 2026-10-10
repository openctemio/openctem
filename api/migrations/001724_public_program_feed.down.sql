-- A followed program becomes a pasted one, suspended until re-imported.
UPDATE bounty_programs SET status = 'paused' WHERE status = 'pending_attestation';
UPDATE bounty_programs SET scope_source = 'paste' WHERE scope_source = 'public_feed';
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_status;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_status
    CHECK (status IN ('active', 'paused', 'ended'));
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'file_import', 'program_api', 'program_file'));
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_confirmed;
DROP INDEX IF EXISTS idx_bounty_programs_public;
DROP INDEX IF EXISTS uq_bounty_programs_public;
ALTER TABLE bounty_programs
    DROP COLUMN IF EXISTS confirmed_targets,
    DROP COLUMN IF EXISTS public_synced_sha256,
    DROP COLUMN IF EXISTS public_program_id;
DROP TABLE IF EXISTS program_feed_sources;
DROP TABLE IF EXISTS program_feed_state;
DROP TABLE IF EXISTS public_programs;
