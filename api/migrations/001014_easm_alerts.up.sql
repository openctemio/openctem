-- EASM alerts through the notification outbox (research/22 P0-7, decision E4;
-- docs/rfcs/RFC-036-easm.md, docs/architecture/easm.md).
--
-- 1. easm_alert_throttle: one row per tenant counting the immediate EASM
--    alerts in the current one-hour window. Alerts over the budget go to the
--    daily digest instead. Updated in the same transaction as the exposure.
-- 2. One pending digest per tenant and day: the digest is a single
--    notification_outbox row (aggregate_type 'easm_digest', aggregate_id
--    derived from tenant and due date) that each digest-class exposure
--    updates. The partial unique index makes that an upsert. Outbox rows are
--    short-lived (archived and deleted once sent), so the index stays small.
CREATE TABLE IF NOT EXISTS easm_alert_throttle (
    tenant_id    UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent         INTEGER     NOT NULL DEFAULT 0,
    CONSTRAINT chk_easm_alert_throttle_sent CHECK (sent >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_notification_outbox_easm_digest
    ON notification_outbox (tenant_id, aggregate_id)
    WHERE aggregate_type = 'easm_digest' AND status = 'pending';
