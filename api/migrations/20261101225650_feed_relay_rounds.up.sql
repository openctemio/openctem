-- Feed relay (docs/rfcs/RFC-142-feed-relay.md): the rounds the platform asks
-- its designated relay sensors to fetch for one feed, and the files they
-- relayed. Feed data is platform-wide catalog data: these tables have no
-- tenant_id by design and hold no tenant data. Only a platform
-- (instance-scope) sensor serves a round; the files are verified against the
-- feed's pinned root by the importer, never trusted from these tables.
CREATE TABLE IF NOT EXISTS feed_relay_rounds (
    id              UUID        PRIMARY KEY,
    -- The designated sensor that claimed the round (NULL: not claimed yet,
    -- and always NULL on the bookkeeping rows that close a cycle).
    sensor_id       UUID        REFERENCES sensors(id) ON DELETE SET NULL,
    claimed_at      TIMESTAMPTZ,
    feed            TEXT        NOT NULL,
    phase           TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'open',
    origins         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    files           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    report          JSONB,
    delivered_bytes BIGINT      NOT NULL DEFAULT 0,
    error_code      TEXT        NOT NULL DEFAULT '',
    error_detail    TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    delivered_at    TIMESTAMPTZ,
    CONSTRAINT chk_feed_relay_rounds_feed CHECK (feed IN ('vulnfeed', 'versioncheck')),
    CONSTRAINT chk_feed_relay_rounds_phase CHECK (phase IN ('head', 'manifests', 'chunks', 'imported', 'failed')),
    CONSTRAINT chk_feed_relay_rounds_status CHECK (status IN ('open', 'done', 'refused', 'expired', 'failed')),
    CONSTRAINT chk_feed_relay_rounds_error CHECK (char_length(error_code) <= 64 AND char_length(error_detail) <= 300),
    CONSTRAINT chk_feed_relay_rounds_bytes CHECK (delivered_bytes >= 0),
    CONSTRAINT chk_feed_relay_rounds_json CHECK (jsonb_typeof(origins) = 'array' AND jsonb_typeof(files) = 'array')
);

COMMENT ON TABLE feed_relay_rounds IS 'Feed relay rounds: files a designated platform relay sensor was asked to fetch and the outcome. Platform-wide, no tenant data.';

-- The oldest open round (claim), the latest rounds of a feed, and a relay
-- sensor's recent rounds (console).
CREATE INDEX IF NOT EXISTS idx_feed_relay_rounds_open ON feed_relay_rounds (created_at) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_feed_relay_rounds_feed ON feed_relay_rounds (feed, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_relay_rounds_sensor ON feed_relay_rounds (sensor_id, delivered_at DESC) WHERE sensor_id IS NOT NULL;

-- The relay spool: the files the relay sensors uploaded, one row per feed
-- and file name, shared by every API replica (the replica holding the
-- feed-relay controller lease copies them into a local working directory
-- before it plans or imports). A file enters only after its size, digest and
-- pin matched; it is still verified by the importer before anything is
-- applied. Re-fetchable: a backup may skip this table's data.
CREATE TABLE IF NOT EXISTS feed_relay_files (
    feed        TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    sha256      CHAR(64)    NOT NULL,
    size        BIGINT      NOT NULL,
    data        BYTEA       NOT NULL,
    round_id    UUID,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (feed, name),
    CONSTRAINT chk_feed_relay_files_feed CHECK (feed IN ('vulnfeed', 'versioncheck')),
    CONSTRAINT chk_feed_relay_files_name CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    CONSTRAINT chk_feed_relay_files_sha CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_feed_relay_files_size CHECK (size >= 0 AND size <= 33554432 AND octet_length(data) = size)
);

COMMENT ON TABLE feed_relay_files IS 'Feed relay spool: relayed feed files awaiting or kept for import. Platform-wide, no tenant data; verified by the importer before use; re-fetchable.';

-- Existing installations keep receiving their feeds directly: record the
-- direct mode for a database that already has users, so only a new install
-- whose bundled sensor setup chose it starts in relay mode.
INSERT INTO platform_settings (key, value, version, source, updated_at)
SELECT 'egress.mode.feeds', '{"mode":"direct"}'::jsonb, 1, 'console', now()
WHERE EXISTS (SELECT 1 FROM admin_users) OR EXISTS (SELECT 1 FROM users)
ON CONFLICT (key) DO NOTHING;

-- The version check records a release feed the relay delivered as origin
-- 'relay' (one-row table: no long lock).
ALTER TABLE version_check_state DROP CONSTRAINT IF EXISTS chk_version_check_state_origin;
ALTER TABLE version_check_state ADD CONSTRAINT chk_version_check_state_origin
    CHECK (origin IS NULL OR origin IN ('online', 'import', 'relay'));
