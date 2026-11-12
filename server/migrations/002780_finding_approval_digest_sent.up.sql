-- When each approver last received the daily digest of finding requests
-- waiting for them (at most one per approver and organization per day). A
-- small per-tenant table; the row goes with the member's account.

CREATE TABLE IF NOT EXISTS finding_approval_digest_sent (
    tenant_id uuid        NOT NULL,
    user_id   uuid        NOT NULL,
    sent_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_finding_approval_digest_sent PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT fk_finding_approval_digest_sent_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_approval_digest_sent_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

COMMENT ON TABLE finding_approval_digest_sent IS
    'Last daily digest of pending finding requests sent to each approver (one per day)';
