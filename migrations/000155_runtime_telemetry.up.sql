-- Runtime telemetry events — append-only stream of EDR/XDR-style
-- observations emitted by agents running on endpoint assets.
--
-- Feeds two downstream consumers:
--   1. IOC correlator (#344 / invariant B6) — matches events against
--      known indicators and auto-reopens related findings.
--   2. Stage-6 dashboards — proves continuous runtime ingest
--      (#355 Q3 gate).
--
-- Schema choices:
--   - event_type is VARCHAR with a CHECK constraint rather than an ENUM
--     because new event types (dns_query, auth_attempt, …) land without
--     an ALTER TYPE migration.
--   - properties JSONB holds event-specific fields. Kept intentionally
--     schemaless so agents on different OSes (Windows EDR, Linux
--     osquery, …) can emit without a wire-format migration every time.
--   - endpoint_asset_id is nullable — during onboarding the agent may
--     not yet know its asset UUID. A nightly reconciler job pairs
--     events with assets by agent_id.
--   - (tenant_id, observed_at) compound index — all downstream reads
--     are per-tenant, time-ordered.

CREATE TABLE IF NOT EXISTS runtime_telemetry_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id            UUID,                     -- emitting agent; FK intentionally soft (agents table lifecycle is independent)
    endpoint_asset_id   UUID REFERENCES assets(id) ON DELETE SET NULL,
    event_type          VARCHAR(40) NOT NULL,
    severity            VARCHAR(10) DEFAULT 'info',
    observed_at         TIMESTAMPTZ NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    properties          JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT chk_rte_event_type CHECK (event_type IN (
        'process_start',
        'process_stop',
        'network_connect',
        'file_write',
        'file_delete',
        'dns_query',
        'auth_attempt',
        'kernel_module_load',
        'other'
    )),
    CONSTRAINT chk_rte_severity CHECK (severity IN ('info','low','medium','high','critical'))
);

CREATE INDEX IF NOT EXISTS idx_rte_tenant_observed_at
    ON runtime_telemetry_events(tenant_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_rte_endpoint_asset
    ON runtime_telemetry_events(endpoint_asset_id, observed_at DESC)
    WHERE endpoint_asset_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rte_event_type_observed_at
    ON runtime_telemetry_events(event_type, observed_at DESC);

COMMENT ON TABLE runtime_telemetry_events IS
    'EDR/XDR-style runtime events emitted by endpoint agents. Append-only, tenant-scoped, feeds IOC correlator.';
