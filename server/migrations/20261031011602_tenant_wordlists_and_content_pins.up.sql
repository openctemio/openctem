-- Organization wordlists and the content a job pinned
-- (docs/architecture/wordlists.md, "Organization lists" and "What a run used").
--
-- tenant_wordlists: an organization's own lists of DNS labels, pasted or
-- uploaded as text, normalised by the API (one label per line). Every
-- enabled list joins the label list of the organization's subdomain
-- enumeration jobs, carried inline under the job signature; nothing is
-- stored on a sensor. version counts content changes; sha256 is of content.
CREATE TABLE tenant_wordlists (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        varchar(64)  NOT NULL,
    description varchar(500) NOT NULL DEFAULT '',
    purpose     varchar(32)  NOT NULL DEFAULT 'dns-labels',
    enabled     boolean      NOT NULL DEFAULT true,
    version     integer      NOT NULL DEFAULT 1,
    lines       integer      NOT NULL,
    sha256      char(64)     NOT NULL,
    content     text         NOT NULL,
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    updated_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_tenant_wordlists_name UNIQUE (tenant_id, name),
    CONSTRAINT chk_tenant_wordlists_name CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$'),
    CONSTRAINT chk_tenant_wordlists_purpose CHECK (purpose IN ('dns-labels')),
    CONSTRAINT chk_tenant_wordlists_version CHECK (version >= 1),
    CONSTRAINT chk_tenant_wordlists_lines CHECK (lines BETWEEN 1 AND 50000),
    CONSTRAINT chk_tenant_wordlists_sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_tenant_wordlists_content CHECK (octet_length(content) <= 1048576)
);

CREATE INDEX idx_tenant_wordlists_tenant ON tenant_wordlists (tenant_id, name);

COMMENT ON TABLE tenant_wordlists IS 'An organization''s own DNS label lists, joined inline into its enumeration jobs.';

CREATE POLICY tenant_wordlists_tenant_isolation ON tenant_wordlists
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

-- What a job read: the packs it pinned (name, version, digest) and the lists
-- generated for it (sha256, lines, source, and the organization lists with
-- their versions), written when the job is signed for a sensor. Nullable:
-- jobs that pin nothing, and every job before this column, have none.
-- Bounded by the writer (a job pins at most 8 packs and 8 lists).
ALTER TABLE commands ADD COLUMN content_pins jsonb;
