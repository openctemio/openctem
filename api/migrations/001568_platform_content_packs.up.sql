-- Platform content packs (api/docs/rfcs/RFC-061-content-packs.md, K2):
-- packs the platform operator ingests (uploads, or upstream releases fetched
-- by URL with a required digest), linted, classified and signed with the
-- platform content key. Kept in their own tables, apart from tenant packs,
-- so no tenant query can reach them by accident and no tenant can write
-- them. Channels (stable, canary) point at one pack per name.

CREATE TABLE platform_content_pack_blobs (
    digest      varchar(71) PRIMARY KEY CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes  bigint NOT NULL CHECK (size_bytes > 0),
    file_count  integer NOT NULL CHECK (file_count > 0),
    storage_key varchar(512) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform_content_packs (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    name          varchar(64) NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    version       varchar(64) NOT NULL CHECK (version ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'),
    kind          varchar(80) NOT NULL CHECK (kind ~ '^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}/[a-z][a-z0-9-]{1,40})$'),
    digest        varchar(71) NOT NULL REFERENCES platform_content_pack_blobs (digest) ON DELETE RESTRICT,
    tier          varchar(2) NOT NULL CHECK (tier IN ('T0', 'T1', 'T2')),
    status        varchar(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    source        varchar(16) NOT NULL CHECK (source IN ('upload', 'https')),
    source_ref    varchar(2048),
    source_digest varchar(71) CHECK (source_digest IS NULL OR source_digest ~ '^sha256:[0-9a-f]{64}$'),
    lint          jsonb NOT NULL DEFAULT '{}'::jsonb,
    signature     jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoke_reason varchar(500),
    CONSTRAINT uq_platform_content_packs_name_version UNIQUE (name, version),
    CONSTRAINT uq_platform_content_packs_id_name UNIQUE (id, name),
    CONSTRAINT chk_platform_content_packs_lint_size CHECK (pg_column_size(lint) <= 200000),
    CONSTRAINT chk_platform_content_packs_revoked CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT chk_platform_content_packs_https CHECK (source <> 'https' OR (source_ref IS NOT NULL AND source_digest IS NOT NULL))
);

CREATE INDEX idx_platform_content_packs_created ON platform_content_packs (created_at DESC);
CREATE INDEX idx_platform_content_packs_name ON platform_content_packs (name, created_at DESC);

-- A channel names a pack of its own name: the composite key makes pointing
-- stable of "nuclei-templates" at a pack of another name impossible.
CREATE TABLE platform_content_channels (
    name       varchar(64) NOT NULL,
    channel    varchar(16) NOT NULL CHECK (channel IN ('stable', 'canary')),
    pack_id    uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, channel),
    CONSTRAINT fk_platform_content_channels_pack FOREIGN KEY (pack_id, name)
        REFERENCES platform_content_packs (id, name) ON DELETE RESTRICT
);

COMMENT ON TABLE platform_content_packs IS
    'Platform content packs (RFC-061): ingested by platform administrators, signed with the platform content key, readable by every organization.';
