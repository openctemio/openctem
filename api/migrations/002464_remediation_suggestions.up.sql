-- Remediation suggestions (docs/rfcs/RFC-098-remediation-tasks.md §5).
--
-- The generator proposes; a person accepts, dismisses (with a reason) or
-- snoozes. A suggestion never creates an action, a task or a membership by
-- itself. identity names what a suggestion proposes (kind, key, target,
-- owner): a new run updates the open suggestion with that identity, and a
-- dismissed one is proposed again only after a material change.
--
-- remediation_key_exclusions remembers findings a person took out of a fix
-- (removed before accepting, detached or moved away), so the generator does
-- not propose them for that key again.
--
-- remediation_suggestion_runs holds one row per tenant: the last generator
-- run (refresh throttle) and the last digest notification.
--
-- Links to tenant rows are composite (tenant_id, ...) foreign keys.
--
-- Live impact: three new, empty tables.

CREATE TABLE IF NOT EXISTS remediation_suggestions (
    id                 uuid          NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id          uuid          NOT NULL,
    kind               varchar(16)   NOT NULL,
    algorithm          varchar(32)   NOT NULL,
    algorithm_version  integer       NOT NULL,
    action_key         varchar(300)  NOT NULL,
    key_kind           varchar(16)   NOT NULL,
    title              varchar(300)  NOT NULL,
    identity           varchar(64)   NOT NULL,
    target_action_id   uuid,
    target_task_id     uuid,
    partitions         jsonb         NOT NULL DEFAULT '[]'::jsonb,
    finding_ids        uuid[]        NOT NULL DEFAULT '{}',
    member_count       integer       NOT NULL DEFAULT 0,
    truncated          integer       NOT NULL DEFAULT 0,
    risk_points        integer       NOT NULL DEFAULT 0,
    risk_parts         jsonb         NOT NULL DEFAULT '{}'::jsonb,
    has_urgent         boolean       NOT NULL DEFAULT false,
    earliest_deadline  timestamptz,
    confidence         numeric(3,2)  NOT NULL,
    fix_spec           jsonb         NOT NULL DEFAULT '{}'::jsonb,
    state              varchar(16)   NOT NULL DEFAULT 'proposed',
    dismiss_reason     varchar(32),
    state_note         varchar(500)  NOT NULL DEFAULT '',
    decided_by         uuid,
    decided_at         timestamptz,
    snoozed_until      timestamptz,
    surfaced_at        timestamptz,
    version            integer       NOT NULL DEFAULT 1,
    created_at         timestamptz   NOT NULL DEFAULT now(),
    updated_at         timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_suggestions PRIMARY KEY (id),
    CONSTRAINT fk_remediation_suggestions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_suggestions_action FOREIGN KEY (tenant_id, target_action_id)
        REFERENCES remediation_actions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_suggestions_task FOREIGN KEY (tenant_id, target_task_id)
        REFERENCES remediation_tasks (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_suggestions_decided_by FOREIGN KEY (decided_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_suggestions_kind CHECK (kind IN ('new_group', 'join', 'task_route')),
    CONSTRAINT chk_remediation_suggestions_state CHECK (state IN
        ('proposed', 'accepted', 'dismissed', 'snoozed', 'superseded', 'expired')),
    CONSTRAINT chk_remediation_suggestions_reason CHECK (dismiss_reason IS NULL OR dismiss_reason IN
        ('wrong_grouping', 'not_actionable', 'already_tracked_elsewhere', 'wrong_owner', 'too_small', 'accepted_risk', 'other')),
    CONSTRAINT chk_remediation_suggestions_confidence CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT chk_remediation_suggestions_members CHECK (member_count >= 0 AND cardinality(finding_ids) <= 2000),
    CONSTRAINT chk_remediation_suggestions_partitions_size CHECK (pg_column_size(partitions) <= 262144)
);

COMMENT ON TABLE remediation_suggestions IS
    'Proposed remediation groups and tasks; a person accepts, dismisses or snoozes them. Never applied by themselves.';

-- One open suggestion per identity.
CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_suggestions_open_identity
    ON remediation_suggestions (tenant_id, identity) WHERE state IN ('proposed', 'snoozed');
CREATE INDEX IF NOT EXISTS idx_remediation_suggestions_identity
    ON remediation_suggestions (tenant_id, identity, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_suggestions_list
    ON remediation_suggestions (tenant_id, state, risk_points DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_suggestions_target_action
    ON remediation_suggestions (target_action_id) WHERE target_action_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_suggestions_target_task
    ON remediation_suggestions (target_task_id) WHERE target_task_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_suggestions_decided_by
    ON remediation_suggestions (decided_by) WHERE decided_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS remediation_key_exclusions (
    tenant_id   uuid          NOT NULL,
    action_key  varchar(300)  NOT NULL,
    finding_id  uuid          NOT NULL,
    reason      varchar(16)   NOT NULL,
    created_by  uuid,
    created_at  timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_key_exclusions PRIMARY KEY (tenant_id, action_key, finding_id),
    CONSTRAINT fk_remediation_key_exclusions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_key_exclusions_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_key_exclusions_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_key_exclusions_reason CHECK (reason IN ('removed', 'detached', 'moved'))
);

COMMENT ON TABLE remediation_key_exclusions IS
    'Findings a person took out of a fix; the suggestion generator does not propose them for that key again.';

CREATE INDEX IF NOT EXISTS idx_remediation_key_exclusions_finding
    ON remediation_key_exclusions (finding_id);
CREATE INDEX IF NOT EXISTS idx_remediation_key_exclusions_created_by
    ON remediation_key_exclusions (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS remediation_suggestion_runs (
    tenant_id       uuid         NOT NULL,
    last_run_at     timestamptz,
    last_digest_at  timestamptz,
    last_stats      jsonb        NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT pk_remediation_suggestion_runs PRIMARY KEY (tenant_id),
    CONSTRAINT fk_remediation_suggestion_runs_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
);

COMMENT ON TABLE remediation_suggestion_runs IS
    'Per tenant: the last suggestion generator run and the last digest notification.';
