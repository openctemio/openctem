-- Coverage alerts on change (docs/rfcs/RFC-093-asset-coverage.md): one row
-- per tenant and alert key (capability, kind, reason) with whether the
-- condition holds, the count when it was last sent and now, and when it was
-- sent and cleared. An alert is sent when its condition appears or its
-- count doubles or halves, never on a timer; the row capability '*', kind
-- 'digest' records the tenant's last digest. It replaces the 20-hour claim
-- keys "coverage-alert:*" in controller_leases (they expire on their own).
--
-- Live impact (2026-10-25): a new, empty table.

CREATE TABLE IF NOT EXISTS asset_coverage_alerts (
    tenant_id   uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    capability  varchar(64) NOT NULL,
    kind        varchar(32) NOT NULL,
    reason      varchar(64) NOT NULL DEFAULT '',
    active      boolean     NOT NULL DEFAULT true,
    sent_count  bigint      NOT NULL DEFAULT 0,
    last_count  bigint      NOT NULL DEFAULT 0,
    sent_at     timestamptz,
    cleared_at  timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_coverage_alerts PRIMARY KEY (tenant_id, capability, kind, reason),
    CONSTRAINT chk_asset_coverage_alerts_counts CHECK (sent_count >= 0 AND last_count >= 0)
);

COMMENT ON TABLE asset_coverage_alerts IS
    'RFC-093: coverage alert state per tenant and (capability, kind, reason); alerts are sent on change, not on a timer.';
