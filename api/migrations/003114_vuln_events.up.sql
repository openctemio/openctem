-- Emerging-threat alerts (docs/rfcs/RFC-117-emerging-threat-alerts.md):
-- a platform-wide log of material vulnerability changes. Public facts only
-- (CVE corpus, KEV, EPSS); no tenant data and no tenant-facing write.

CREATE TABLE vuln_events (
    id            BIGSERIAL PRIMARY KEY,
    vuln_id       TEXT NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 64),
    kind          TEXT NOT NULL CHECK (kind IN ('published', 'ranges_added', 'ranges_widened', 'severity_up',
                                                'kev_added', 'epss_crossed', 'rejected')),
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_at     TIMESTAMPTZ,
    feed_sequence BIGINT,
    detail        JSONB NOT NULL DEFAULT '{}' CHECK (length(detail::text) <= 2048)
);
CREATE INDEX idx_vuln_events_at ON vuln_events (at);
CREATE INDEX idx_vuln_events_vuln ON vuln_events (vuln_id, at);
COMMENT ON TABLE vuln_events IS
    'Material vulnerability changes seen by the platform (RFC-117): new CVE with ranges, ranges widened, severity up, KEV add, EPSS crossing, rejection. Public facts only; read by the alert planner.';

-- What the emitter last saw of each vulnerability, so a change is reported
-- once and a replay reports nothing.
CREATE TABLE vuln_event_state (
    vuln_id     TEXT PRIMARY KEY CHECK (length(vuln_id) BETWEEN 1 AND 64),
    status      TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    cvss_score  NUMERIC(3,1),
    product_ids UUID[] NOT NULL DEFAULT '{}',
    range_count INTEGER NOT NULL DEFAULT 0,
    in_kev      BOOLEAN NOT NULL DEFAULT false,
    epss_band   SMALLINT NOT NULL DEFAULT 0 CHECK (epss_band BETWEEN 0 AND 2),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE vuln_event_state IS
    'Last state of each vulnerability the event emitter compared (RFC-117). Platform-wide, no tenant data.';

-- Progress of the emitter and of the alert planner.
CREATE TABLE vuln_event_cursors (
    name       TEXT PRIMARY KEY CHECK (name IN ('corpus', 'kev', 'epss', 'planner')),
    at         TIMESTAMPTZ,
    key        TEXT NOT NULL DEFAULT '',
    position   BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
