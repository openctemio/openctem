-- Indicators of Compromise (IOC) + match log.
--
-- Invariant B6 — runtime telemetry that hits a known IOC linked to a
-- closed finding auto-reopens that finding. Without this table there
-- is no catalogue to match against, so the correlator has nothing to
-- do.
--
-- Design notes:
--
--   - IOC is tenant-scoped. Two tenants can observe the same IP on
--     their network with completely different context; leaking across
--     tenants would false-positive everyone at once.
--
--   - `value_normalised` is the column the correlator queries. Lower-
--     case + whitespace-stripped so "1.2.3.4" and " 1.2.3.4 " dedup.
--     Raw `value` is kept for display.
--
--   - `source_finding_id` links back to the finding that produced this
--     IOC (eg. a malicious IP spotted in a vuln scan). When the
--     correlator fires, this is the finding it reopens.
--
--   - `active` defaults true. An operator can toggle false to silence
--     a stale indicator (eg. EDR signature decayed) without deleting
--     the history row.
--
--   - (tenant_id, ioc_type, value_normalised) compound unique index —
--     prevents duplicate indicators per tenant and is the exact
--     shape the correlator looks up on.

CREATE TABLE IF NOT EXISTS iocs (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ioc_type           VARCHAR(20) NOT NULL,
    value              TEXT NOT NULL,
    value_normalised   TEXT NOT NULL,
    source_finding_id  UUID REFERENCES findings(id) ON DELETE SET NULL,
    source             VARCHAR(40),                 -- "scan_finding" | "threat_feed" | "manual"
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    confidence         SMALLINT NOT NULL DEFAULT 75 CHECK (confidence BETWEEN 0 AND 100),
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ioc_type CHECK (ioc_type IN (
        'ip',
        'domain',
        'url',
        'file_hash',
        'process_name',
        'user_agent'
    )),
    CONSTRAINT chk_ioc_source CHECK (source IS NULL OR source IN (
        'scan_finding',
        'threat_feed',
        'manual'
    ))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_iocs_tenant_type_value
    ON iocs(tenant_id, ioc_type, value_normalised);

CREATE INDEX IF NOT EXISTS idx_iocs_source_finding
    ON iocs(source_finding_id)
    WHERE source_finding_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_iocs_active_tenant
    ON iocs(tenant_id, active)
    WHERE active = TRUE;

COMMENT ON TABLE iocs IS
    'Tenant-scoped indicators of compromise. Matched against runtime_telemetry_events to auto-reopen related findings (invariant B6).';

-- Match log — one row per correlator hit. Kept separately from
-- runtime_telemetry_events so a single event that triggers multiple
-- IOCs records each match individually, and so deleting telemetry
-- rows during retention cleanup doesn't drop the audit trail of WHY
-- a finding was reopened.
CREATE TABLE IF NOT EXISTS ioc_matches (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ioc_id               UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    telemetry_event_id   UUID REFERENCES runtime_telemetry_events(id) ON DELETE SET NULL,
    finding_id           UUID REFERENCES findings(id) ON DELETE SET NULL,
    reopened             BOOLEAN NOT NULL DEFAULT FALSE,
    matched_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_matches_tenant_matched_at
    ON ioc_matches(tenant_id, matched_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_matches_finding
    ON ioc_matches(finding_id, matched_at DESC)
    WHERE finding_id IS NOT NULL;

-- Idempotency: same agent retry replays the same event. Dedupe
-- (ioc_id, telemetry_event_id) so a retried batch doesn't inflate
-- the ioc_matches count. Partial — telemetry_event_id is nullable
-- when the match arrived via a path that doesn't carry one.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ioc_matches_ioc_event
    ON ioc_matches(ioc_id, telemetry_event_id)
    WHERE telemetry_event_id IS NOT NULL;

COMMENT ON TABLE ioc_matches IS
    'Audit trail: one row per IOC hit observed in runtime telemetry. Feeds the "why was this finding reopened?" UI.';
