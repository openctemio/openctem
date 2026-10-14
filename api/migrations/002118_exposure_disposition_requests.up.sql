-- Four-eyes on exposure dispositions (api/docs/architecture/
-- finding-status-lifecycle.md, "Four-eyes on exposure dispositions"):
-- accepting the risk of, or marking a false positive, a high or critical
-- exposure (leaked credentials included) takes two people. The first approver's
-- call stores a pending request here; a different approver confirms it, and
-- only then does the exposure change state. The owner may confirm their own
-- request only when nobody else can approve (self_approved, audited Critical).
--
-- At most one pending request per exposure. Rows are deleted with their
-- exposure or organization; people who leave are kept as NULL.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS exposure_disposition_requests (
    id                uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id         uuid         NOT NULL,
    exposure_event_id uuid         NOT NULL,
    requested_state   varchar(20)  NOT NULL,
    requested_by      uuid,
    reason            text         NOT NULL DEFAULT '',
    status            varchar(20)  NOT NULL DEFAULT 'pending',
    decided_by        uuid,
    decided_at        timestamptz,
    decision_reason   text         NOT NULL DEFAULT '',
    self_approved     boolean      NOT NULL DEFAULT false,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_exposure_disposition_requests PRIMARY KEY (id),
    CONSTRAINT fk_exposure_disposition_requests_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_exposure_disposition_requests_exposure FOREIGN KEY (exposure_event_id)
        REFERENCES exposure_events (id) ON DELETE CASCADE,
    CONSTRAINT fk_exposure_disposition_requests_requested_by FOREIGN KEY (requested_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_exposure_disposition_requests_decided_by FOREIGN KEY (decided_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_exposure_disposition_requests_state
        CHECK (requested_state IN ('accepted', 'false_positive')),
    CONSTRAINT chk_exposure_disposition_requests_status
        CHECK (status IN ('pending', 'approved', 'rejected', 'canceled')),
    CONSTRAINT chk_exposure_disposition_requests_reason
        CHECK (length(reason) <= 1000 AND length(decision_reason) <= 1000)
);

COMMENT ON TABLE exposure_disposition_requests IS
    'Pending and decided four-eyes requests to accept or mark false positive a high or critical exposure.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_exposure_disposition_requests_pending
    ON exposure_disposition_requests (tenant_id, exposure_event_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_exposure_disposition_requests_exposure
    ON exposure_disposition_requests (exposure_event_id);
CREATE INDEX IF NOT EXISTS idx_exposure_disposition_requests_requested_by
    ON exposure_disposition_requests (requested_by) WHERE requested_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exposure_disposition_requests_decided_by
    ON exposure_disposition_requests (decided_by) WHERE decided_by IS NOT NULL;

-- Policy in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS exposure_disposition_requests_tenant_isolation ON exposure_disposition_requests;
CREATE POLICY exposure_disposition_requests_tenant_isolation ON exposure_disposition_requests
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
