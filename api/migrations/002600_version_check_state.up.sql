-- The version check's state (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md):
-- one row for the instance. It holds the last verified release feed, the
-- sequence and key set version applied (a lower one is refused), and the
-- schedule the API replicas share (the replica whose conditional update moves
-- next_check_at fetches). Instance-level, no tenant data: the table has no
-- tenant_id and only the platform console reads it.
-- A new, empty table.

CREATE TABLE version_check_state (
    id                   smallint PRIMARY KEY DEFAULT 1,
    feed                 jsonb,
    origin               text,
    applied_sequence     bigint NOT NULL DEFAULT 0,
    keyset_version       bigint NOT NULL DEFAULT 0,
    applied_at           timestamp with time zone,
    last_attempt_at      timestamp with time zone,
    last_error           text,
    consecutive_failures integer NOT NULL DEFAULT 0,
    next_check_at        timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_version_check_state_singleton CHECK (id = 1),
    CONSTRAINT chk_version_check_state_origin CHECK (origin IS NULL OR origin IN ('online', 'import')),
    CONSTRAINT chk_version_check_state_feed_size CHECK (feed IS NULL OR octet_length(feed::text) <= 262144),
    CONSTRAINT chk_version_check_state_error_size CHECK (last_error IS NULL OR length(last_error) <= 500)
);

COMMENT ON TABLE version_check_state IS 'Version check: the last verified release feed and the shared check schedule; one row (RFC-105)';
