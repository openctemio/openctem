-- Private programs (RFC-065 §15): a program a person follows by invitation
-- is imported from a file or entered by hand, is private by default, and
-- each person accepts its terms and confidentiality before seeing them.
--
-- Live impact: bounty_programs is small; the new columns have constant
-- defaults (no rewrite). Existing programs keep the visibility they have
-- today ('public': members and full-data callers); new ones default to
-- private.

ALTER TABLE bounty_programs
    ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'public',
    ADD COLUMN IF NOT EXISTS terms_text text NOT NULL DEFAULT '';
ALTER TABLE bounty_programs ALTER COLUMN visibility SET DEFAULT 'private';
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_visibility
    CHECK (visibility IN ('private', 'public'));
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_terms_text
    CHECK (length(terms_text) <= 20000);

-- The program link is optional: a private program page is behind its
-- platform login.
-- expand-contract-ok: the constraint only widens; the old api always writes an https link
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_url;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_url
    CHECK (program_url = '' OR (program_url LIKE 'https://%' AND length(program_url) <= 500));
ALTER TABLE bounty_programs ALTER COLUMN program_url SET DEFAULT '';

-- expand-contract-ok: the constraint only widens; the old api never writes file_import
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'file_import', 'program_api', 'program_file'));

-- Each person's acceptance of a program's terms and confidentiality. A
-- private program's details need a row whose hash is the program's current
-- terms_sha256; a change of terms asks everyone again.
CREATE TABLE IF NOT EXISTS bounty_program_attestations (
    tenant_id    uuid        NOT NULL,
    program_id   uuid        NOT NULL,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    terms_sha256 text        NOT NULL,
    accepted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, program_id, user_id),
    CONSTRAINT fk_bounty_program_attestations_program FOREIGN KEY (tenant_id, program_id)
        REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_bounty_program_attestations_terms CHECK (terms_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_bounty_program_attestations_user
    ON bounty_program_attestations (tenant_id, user_id);

-- The person whose attestation is in force on a program has accepted its
-- current terms.
INSERT INTO bounty_program_attestations (tenant_id, program_id, user_id, terms_sha256, accepted_at)
SELECT p.tenant_id, p.id, p.accepted_by, p.terms_sha256, p.accepted_at
FROM bounty_programs p
JOIN users u ON u.id = p.accepted_by
WHERE p.accepted_by IS NOT NULL AND p.accepted_at IS NOT NULL
ON CONFLICT DO NOTHING;

COMMENT ON COLUMN bounty_programs.visibility IS 'private: members and owners only, views audited, per-person attestation; public: program data scope (RFC-065 §15)';
COMMENT ON TABLE bounty_program_attestations IS 'Each person''s acceptance of a program''s current terms and confidentiality (RFC-065 §15)';
