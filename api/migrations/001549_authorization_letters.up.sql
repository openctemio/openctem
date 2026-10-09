-- Authorization letters (RFC-065 §13): a client's written permission (a
-- pentest engagement) uploaded once and named by the scope entries it
-- authorizes. An entry with authorization_source 'authorization_letter'
-- names its letter and authorizes only while the letter is valid.
-- New table; scope_targets gets one nullable column (no rewrite).

CREATE TABLE authorization_letters (
    id            uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id     uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    title         text        NOT NULL,
    issuer        text        NOT NULL DEFAULT '',
    reference     text        NOT NULL DEFAULT '',
    valid_from    timestamptz NOT NULL,
    valid_until   timestamptz NOT NULL,
    attachment_id uuid        NOT NULL,
    file_sha256   text        NOT NULL,
    uploaded_by   uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoked_by    uuid,
    PRIMARY KEY (id),
    CONSTRAINT uq_authorization_letters_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_authorization_letters_title CHECK (length(btrim(title)) BETWEEN 1 AND 200),
    CONSTRAINT chk_authorization_letters_issuer CHECK (length(issuer) <= 200),
    CONSTRAINT chk_authorization_letters_reference CHECK (length(reference) <= 200),
    CONSTRAINT chk_authorization_letters_window CHECK (valid_until > valid_from AND valid_until <= valid_from + interval '731 days'),
    CONSTRAINT chk_authorization_letters_sha CHECK (file_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE INDEX idx_authorization_letters_tenant ON authorization_letters (tenant_id, valid_until);

COMMENT ON TABLE authorization_letters IS 'Letters of authorization (pentest engagements) that scope entries name as their authority (RFC-065)';

ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS letter_id uuid;
ALTER TABLE scope_targets
    ADD CONSTRAINT fk_scope_targets_letter FOREIGN KEY (tenant_id, letter_id)
    REFERENCES authorization_letters (tenant_id, id) ON DELETE RESTRICT;
ALTER TABLE scope_targets
    ADD CONSTRAINT chk_scope_targets_letter
    CHECK ((authorization_source = 'authorization_letter') = (letter_id IS NOT NULL)) NOT VALID;
ALTER TABLE scope_targets VALIDATE CONSTRAINT chk_scope_targets_letter;
CREATE INDEX IF NOT EXISTS idx_scope_targets_letter ON scope_targets (letter_id) WHERE letter_id IS NOT NULL;

COMMENT ON COLUMN scope_targets.letter_id IS 'The authorization letter an authorization_letter entry names; it authorizes only while the letter is valid';
