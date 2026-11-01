-- Feed relay rounds (docs/rfcs/RFC-142-feed-relay.md): what the platform asked
-- its designated relay sensor to fetch for one feed, and what came back. Feed
-- data is platform-wide catalog data: this table has no tenant_id by design
-- and holds no tenant data. Only a platform (instance-scope) sensor serves a
-- round; the files themselves are verified against the feed's pinned root by
-- the importer, never trusted from this table.
CREATE TABLE IF NOT EXISTS feed_relay_rounds (
    id           UUID        PRIMARY KEY,
    sensor_id    UUID        NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    feed         TEXT        NOT NULL,
    phase        TEXT        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'open',
    origins      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    files        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    report       JSONB,
    error_code   TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    CONSTRAINT chk_feed_relay_rounds_feed CHECK (feed IN ('vulnfeed', 'versioncheck')),
    CONSTRAINT chk_feed_relay_rounds_phase CHECK (phase IN ('head', 'manifests', 'chunks', 'imported', 'failed')),
    CONSTRAINT chk_feed_relay_rounds_status CHECK (status IN ('open', 'done', 'refused', 'expired', 'failed')),
    CONSTRAINT chk_feed_relay_rounds_error CHECK (char_length(error_code) <= 64),
    CONSTRAINT chk_feed_relay_rounds_json CHECK (jsonb_typeof(origins) = 'array' AND jsonb_typeof(files) = 'array')
);

COMMENT ON TABLE feed_relay_rounds IS 'Feed relay rounds: files a platform relay sensor was asked to fetch and the outcome. Platform-wide, no tenant data.';

-- The relay sensor's next open round, and the latest rounds of a feed.
CREATE INDEX IF NOT EXISTS idx_feed_relay_rounds_open ON feed_relay_rounds (sensor_id, created_at) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_feed_relay_rounds_feed ON feed_relay_rounds (feed, created_at DESC);

-- The version check records a release feed the relay delivered as origin
-- 'relay' (one-row table: no long lock).
ALTER TABLE version_check_state DROP CONSTRAINT IF EXISTS chk_version_check_state_origin;
ALTER TABLE version_check_state ADD CONSTRAINT chk_version_check_state_origin
    CHECK (origin IS NULL OR origin IN ('online', 'import', 'relay'));
