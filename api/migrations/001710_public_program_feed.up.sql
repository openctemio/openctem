-- Public program monitor (RFC-065 §16): the platform catalog of public
-- bug-bounty programs imported from the signed program feed, the feed's
-- applied state, and the organization programs that follow a catalog
-- program (subscriptions: entries inactive until a member accepts the
-- terms).
--
-- public_programs is global: a public program's published scope is public
-- data, written only by the feed importer. Live impact: new tables; the
-- bounty_programs change adds a nullable column and widens two checks.

CREATE TABLE IF NOT EXISTS public_programs (
    id            uuid        NOT NULL DEFAULT uuid_generate_v7(),
    feed_id       text        NOT NULL,
    platform      text        NOT NULL,
    handle        text        NOT NULL,
    name          text        NOT NULL,
    program_url   text        NOT NULL DEFAULT '',
    offers_bounty boolean     NOT NULL DEFAULT false,
    open          boolean     NOT NULL DEFAULT true,
    scope_items   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    rules         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    terms_text    text        NOT NULL DEFAULT '',
    terms_sha256  text        NOT NULL,
    source        text        NOT NULL,
    as_of         timestamptz NOT NULL,
    removed_at    timestamptz,
    feed_sequence bigint      NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT uq_public_programs_feed_id UNIQUE (feed_id),
    CONSTRAINT chk_public_programs_feed_id CHECK (length(feed_id) <= 160 AND feed_id = platform || ':' || handle),
    CONSTRAINT chk_public_programs_name CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    CONSTRAINT chk_public_programs_url CHECK (program_url = '' OR (program_url LIKE 'https://%' AND length(program_url) <= 500)),
    CONSTRAINT chk_public_programs_terms CHECK (terms_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_public_programs_terms_text CHECK (length(terms_text) <= 20000),
    CONSTRAINT chk_public_programs_items CHECK (jsonb_typeof(scope_items) = 'array'),
    CONSTRAINT chk_public_programs_rules CHECK (jsonb_typeof(rules) = 'object')
);
CREATE INDEX IF NOT EXISTS idx_public_programs_listed ON public_programs (lower(name)) WHERE removed_at IS NULL;

COMMENT ON TABLE public_programs IS 'Catalog of public bug-bounty programs from the signed program feed (RFC-065 §16); global, written only by the importer';

CREATE TABLE IF NOT EXISTS program_feed_state (
    id               smallint    NOT NULL DEFAULT 1,
    applied_sequence bigint      NOT NULL,
    keyset_version   bigint      NOT NULL,
    applied_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT chk_program_feed_state_single CHECK (id = 1)
);
COMMENT ON TABLE program_feed_state IS 'The program feed sequence and key-set version last applied; a lower one is refused (RFC-065 §16)';

ALTER TABLE bounty_programs ADD COLUMN IF NOT EXISTS public_program_id uuid
    REFERENCES public_programs (id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_bounty_programs_public
    ON bounty_programs (tenant_id, public_program_id) WHERE public_program_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bounty_programs_public ON bounty_programs (public_program_id)
    WHERE public_program_id IS NOT NULL;

-- expand-contract-ok: the constraint only widens; the old api never writes public_feed
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'file_import', 'program_api', 'program_file', 'public_feed'));
-- expand-contract-ok: the constraint only widens; the old api never writes pending_attestation
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_status;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_status
    CHECK (status IN ('active', 'paused', 'ended', 'pending_attestation'));

COMMENT ON COLUMN bounty_programs.public_program_id IS 'The catalog program this organization program follows (scope_source public_feed)';
