DROP TABLE IF EXISTS bounty_program_attestations;

UPDATE bounty_programs SET scope_source = 'paste' WHERE scope_source = 'file_import';
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'program_api', 'program_file'));

-- A program entered without a link gets a placeholder the old check accepts.
UPDATE bounty_programs SET program_url = 'https://program-link-not-set.invalid/' WHERE program_url = '';
ALTER TABLE bounty_programs ALTER COLUMN program_url DROP DEFAULT;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_url;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_url
    CHECK (program_url LIKE 'https://%' AND length(program_url) <= 500);

ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_terms_text;
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_visibility;
ALTER TABLE bounty_programs
    DROP COLUMN IF EXISTS terms_text,
    DROP COLUMN IF EXISTS visibility;
