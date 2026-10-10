-- Public program monitor (RFC-065 §16): the platform catalog of public
-- bug-bounty and disclosure programs imported from the signed program feed
-- (record schema openctem.programfeed/v1), the feed's applied state, and the
-- organization programs that follow a catalog program (entries inactive
-- until a member accepts the terms; inferred targets only once confirmed).
--
-- public_programs is global: a public program's published record is public
-- data, written only by the feed importer. Live impact: new tables;
-- bounty_programs gets nullable or defaulted columns and two widened checks.

CREATE TABLE IF NOT EXISTS public_programs (
    id               uuid        NOT NULL DEFAULT uuid_generate_v7(),
    feed_id          text        NOT NULL,
    source           text        NOT NULL,
    platform         text        NOT NULL DEFAULT '',
    handle           text        NOT NULL,
    name             text        NOT NULL,
    program_url      text        NOT NULL DEFAULT '',
    program_type     text        NOT NULL,
    status           text        NOT NULL,
    offers_bounty    boolean     NOT NULL DEFAULT false,
    scope_published  boolean     NOT NULL DEFAULT false,
    scope_items      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    rules            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    terms_text       text        NOT NULL DEFAULT '',
    terms_url        text        NOT NULL DEFAULT '',
    terms_doc_sha256 text        NOT NULL DEFAULT '',
    content_sha256   text        NOT NULL,
    provenance       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    feed_stream      text        NOT NULL DEFAULT 'signed',
    as_of            timestamptz NOT NULL,
    removed_at       timestamptz,
    feed_sequence    bigint      NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT uq_public_programs_feed_id UNIQUE (feed_id),
    CONSTRAINT chk_public_programs_feed_id CHECK (length(feed_id) <= 161 AND feed_id = source || ':' || handle),
    CONSTRAINT chk_public_programs_name CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    CONSTRAINT chk_public_programs_type CHECK (program_type IN ('bounty', 'vdp')),
    CONSTRAINT chk_public_programs_status CHECK (status IN ('open', 'paused', 'closed')),
    CONSTRAINT chk_public_programs_url CHECK (program_url = '' OR ((program_url LIKE 'https://%' OR program_url LIKE 'http://%') AND length(program_url) <= 2048)),
    CONSTRAINT chk_public_programs_terms_url CHECK (terms_url = '' OR ((terms_url LIKE 'https://%' OR terms_url LIKE 'http://%') AND length(terms_url) <= 2048)),
    CONSTRAINT chk_public_programs_terms_doc CHECK (terms_doc_sha256 = '' OR terms_doc_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_public_programs_content CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_public_programs_terms_text CHECK (length(terms_text) <= 20000),
    CONSTRAINT chk_public_programs_items CHECK (jsonb_typeof(scope_items) = 'array'),
    CONSTRAINT chk_public_programs_rules CHECK (jsonb_typeof(rules) = 'object'),
    CONSTRAINT chk_public_programs_provenance CHECK (jsonb_typeof(provenance) = 'object'),
    CONSTRAINT chk_public_programs_stream CHECK (feed_stream IN ('signed', 'local'))
);
CREATE INDEX IF NOT EXISTS idx_public_programs_listed ON public_programs (lower(name)) WHERE removed_at IS NULL;

COMMENT ON TABLE public_programs IS 'Catalog of public bug-bounty and disclosure programs from the signed program feed (RFC-065 §16); global, written only by the importer. Targets are never permission to test.';

CREATE TABLE IF NOT EXISTS program_feed_state (
    id               smallint    NOT NULL DEFAULT 1,
    applied_sequence bigint      NOT NULL,
    keyset_version   bigint      NOT NULL,
    applied_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT chk_program_feed_state_stream CHECK (id IN (1, 2))
);
COMMENT ON TABLE program_feed_state IS 'The sequence and key-set version last applied per stream (1 signed feed, 2 local bundle); a lower one is refused (RFC-065 §16)';

-- The operator's local bundle source (owner option A): off until a
-- platform administrator enables it (step-up and a reason, audited).
CREATE TABLE IF NOT EXISTS program_feed_sources (
    source     text        NOT NULL,
    enabled    boolean     NOT NULL DEFAULT false,
    reason     text        NOT NULL DEFAULT '',
    changed_by text        NOT NULL DEFAULT '',
    changed_at timestamptz,
    PRIMARY KEY (source),
    CONSTRAINT chk_program_feed_sources_source CHECK (source IN ('local_bundle')),
    CONSTRAINT chk_program_feed_sources_reason CHECK (length(reason) <= 500)
);
COMMENT ON TABLE program_feed_sources IS 'Platform switches of program feed sources; local_bundle reads PROGRAMFEED_LOCAL_BUNDLE_DIR only when enabled (RFC-065 §16.6)';

ALTER TABLE bounty_programs
    ADD COLUMN IF NOT EXISTS public_program_id    uuid REFERENCES public_programs (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS public_synced_sha256 text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS confirmed_targets    text[] NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX IF NOT EXISTS uq_bounty_programs_public
    ON bounty_programs (tenant_id, public_program_id) WHERE public_program_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bounty_programs_public ON bounty_programs (public_program_id)
    WHERE public_program_id IS NOT NULL;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_confirmed
    CHECK (cardinality(confirmed_targets) <= 2000);

-- expand-contract-ok: the constraint only widens; the old api never writes public_feed
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_source;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_source
    CHECK (scope_source IN ('paste', 'file_import', 'program_api', 'program_file', 'public_feed'));
-- expand-contract-ok: the constraint only widens; the old api never writes pending_attestation
ALTER TABLE bounty_programs DROP CONSTRAINT IF EXISTS chk_bounty_programs_status;
ALTER TABLE bounty_programs ADD CONSTRAINT chk_bounty_programs_status
    CHECK (status IN ('active', 'paused', 'ended', 'pending_attestation'));

COMMENT ON COLUMN bounty_programs.public_program_id IS 'The catalog program this organization program follows (scope_source public_feed)';
COMMENT ON COLUMN bounty_programs.confirmed_targets IS 'Targets the feed only inferred that a member confirmed for this program';
