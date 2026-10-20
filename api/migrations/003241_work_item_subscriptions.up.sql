-- Watchers of findings and remediation tasks (RFC-120). One row per person and
-- item: `subscribed` (told about the item) or `unsubscribed` (an explicit stop
-- that later participation never overrides). Watching grants nothing: reads,
-- sends and lists re-check membership, data scope and pentest visibility.
--
-- Tenant isolation is the database's: (tenant_id, finding_id) and
-- (tenant_id, task_id) are composite foreign keys, so a row cannot name an item
-- of another tenant. A new empty table: safe on a populated database.

CREATE TABLE IF NOT EXISTS work_item_subscriptions (
    id          uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid         NOT NULL,
    finding_id  uuid,
    task_id     uuid,
    user_id     uuid         NOT NULL,
    state       varchar(12)  NOT NULL DEFAULT 'subscribed',
    reason      varchar(16)  NOT NULL,
    added_by    uuid,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_work_item_subscriptions PRIMARY KEY (id),
    CONSTRAINT fk_wis_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_wis_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_wis_task FOREIGN KEY (tenant_id, task_id)
        REFERENCES remediation_tasks (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_wis_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_wis_added_by FOREIGN KEY (added_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_wis_one_item CHECK (num_nonnulls(finding_id, task_id) = 1),
    CONSTRAINT chk_wis_state CHECK (state IN ('subscribed', 'unsubscribed')),
    CONSTRAINT chk_wis_reason CHECK (reason IN ('manual', 'added', 'assigned', 'commented', 'status_changed',
                                                'fix_claimed', 'mentioned', 'approval', 'created'))
);

COMMENT ON TABLE work_item_subscriptions IS
    'Watchers of a finding or a remediation task: explicit subscribe or unsubscribe, and people added by taking part (reason). Grants no access.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_wis_finding_user
    ON work_item_subscriptions (tenant_id, finding_id, user_id) WHERE finding_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_wis_task_user
    ON work_item_subscriptions (tenant_id, task_id, user_id) WHERE task_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_wis_user
    ON work_item_subscriptions (tenant_id, user_id) WHERE state = 'subscribed';
CREATE INDEX IF NOT EXISTS idx_wis_added_by
    ON work_item_subscriptions (added_by) WHERE added_by IS NOT NULL;
