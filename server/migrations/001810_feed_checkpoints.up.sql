-- Durable progress of the chunked feed importers (docs/architecture/
-- feed-transfer.md): one row per feed, the last sequence applied completely
-- and the bundle in progress
-- (its sequence, kind, manifest digest and the next chunk to apply).
-- Feed data is platform-wide catalog data: this table has no tenant_id by
-- design and holds no tenant data.
CREATE TABLE IF NOT EXISTS feed_checkpoints (
    feed                 TEXT        PRIMARY KEY,
    applied_sequence     BIGINT      NOT NULL DEFAULT 0,
    in_progress_sequence BIGINT      NOT NULL DEFAULT 0,
    kind                 TEXT        NOT NULL DEFAULT '',
    manifest_sha256      TEXT        NOT NULL DEFAULT '',
    next_chunk           INTEGER     NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_feed_checkpoints_feed CHECK (feed IN ('programfeed', 'programfeed-local', 'vulnfeed')),
    CONSTRAINT chk_feed_checkpoints_kind CHECK (kind IN ('', 'snapshot', 'delta')),
    CONSTRAINT chk_feed_checkpoints_numbers CHECK (applied_sequence >= 0 AND in_progress_sequence >= 0 AND next_chunk >= 0),
    CONSTRAINT chk_feed_checkpoints_manifest CHECK (manifest_sha256 = '' OR manifest_sha256 ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE feed_checkpoints IS 'Per feed: last sequence applied completely and the chunked bundle in progress. Platform-wide, no tenant data.';

-- The first chunked import continues from the sequence the whole-bundle
-- importer applied (program_feed_state: 1 signed feed, 2 local bundle).
INSERT INTO feed_checkpoints (feed, applied_sequence, updated_at)
SELECT CASE id WHEN 1 THEN 'programfeed' ELSE 'programfeed-local' END, applied_sequence, applied_at
FROM program_feed_state
ON CONFLICT (feed) DO NOTHING;
