-- Automation run trace and deliveries (RFC-125 §5).
--
-- Every step records how many subjects reached it (in_count), how many it
-- acted on or would act on (out_count) and, per reason, how many it left
-- alone (skipped). automation_deliveries records every message or ticket a
-- step sent (live) or would have sent (simulate, never sent), with a payload
-- cut down to an allow-list of fields. Simulate runs are kept 30 days, live
-- runs 180 days (the automation-run-retention controller); deliveries go
-- with their run.

ALTER TABLE automation_run_steps
    ADD COLUMN in_count  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN out_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN skipped   JSONB   NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN automation_run_steps.skipped IS 'Subjects the step left alone, per reason: {"condition_false": 1}';

CREATE TABLE automation_deliveries (
    id              UUID         NOT NULL DEFAULT uuid_generate_v7() PRIMARY KEY,
    tenant_id       UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    run_id          UUID         NOT NULL REFERENCES automation_runs (id) ON DELETE CASCADE,
    node_key        VARCHAR(100) NOT NULL,
    channel         VARCHAR(20)  NOT NULL,
    target          VARCHAR(255) NOT NULL DEFAULT '',
    mode            VARCHAR(10)  NOT NULL CHECK (mode IN ('simulate', 'live')),
    status          VARCHAR(20)  NOT NULL CHECK (status IN ('simulated', 'sent', 'failed', 'held')),
    attempts        INTEGER      NOT NULL DEFAULT 0,
    idempotency_key VARCHAR(200) NOT NULL,
    payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    external_ref    VARCHAR(255) NOT NULL DEFAULT '',
    error           TEXT         NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_automation_deliveries_idempotency UNIQUE (tenant_id, idempotency_key),
    -- A simulated delivery is never sent.
    CONSTRAINT chk_automation_deliveries_simulated CHECK ((mode = 'simulate') = (status = 'simulated'))
);

CREATE INDEX idx_automation_deliveries_run ON automation_deliveries (tenant_id, run_id);

COMMENT ON TABLE automation_deliveries IS 'Messages and tickets automation steps sent (live) or would have sent (simulate); allow-listed payload fields only';

-- The retention controller deletes by mode and age.
CREATE INDEX idx_automation_runs_mode_created ON automation_runs (mode, created_at);

DROP POLICY IF EXISTS automation_deliveries_tenant_isolation ON automation_deliveries;
CREATE POLICY automation_deliveries_tenant_isolation ON automation_deliveries
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
