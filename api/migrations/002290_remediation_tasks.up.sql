-- Remediation actions, tasks and task membership
-- (docs/rfcs/RFC-098-remediation-tasks.md).
--
-- An action is WHAT fixes a set of findings (one upgrade, one secret
-- rotation, or a fix a person named). A task is WHO does that fix and BY
-- WHEN: one owner (a user and/or a group), the deadline and a state derived
-- from its member findings. A finding is the primary member of at most one
-- active task (it can be a "related" member of others). Membership is
-- history: a finding that leaves keeps its row with left_at set.
--
-- Rows are only ever created by a person (by hand or by accepting a
-- suggestion); no algorithm creates an action or a task.
--
-- Live impact: four new, empty tables. The foreign keys to findings and
-- remediation_campaigns are checked against the new (empty) tables only.

CREATE TABLE IF NOT EXISTS remediation_actions (
    id          uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid         NOT NULL,
    action_key  varchar(300) NOT NULL,
    kind        varchar(16)  NOT NULL,
    title       varchar(300) NOT NULL,
    fix_spec    jsonb        NOT NULL DEFAULT '{}'::jsonb,
    origin      varchar(16)  NOT NULL,
    created_by  uuid,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_actions PRIMARY KEY (id),
    CONSTRAINT fk_remediation_actions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_actions_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_actions_kind CHECK (kind IN ('upgrade', 'rotate', 'sol', 'manual')),
    CONSTRAINT chk_remediation_actions_origin CHECK (origin IN ('manual', 'suggestion')),
    CONSTRAINT chk_remediation_actions_fix_spec_size CHECK (pg_column_size(fix_spec) <= 65536)
);

COMMENT ON TABLE remediation_actions IS
    'What fixes a set of findings (an upgrade, a secret rotation, or a fix a person named); created only by a person.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_actions_key
    ON remediation_actions (tenant_id, action_key);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_created_by
    ON remediation_actions (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id                  uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id           uuid         NOT NULL,
    action_id           uuid         NOT NULL,
    campaign_id         uuid,
    title               varchar(300) NOT NULL,
    description         text         NOT NULL DEFAULT '',
    assignee_user_id    uuid,
    assignee_group_id   uuid,
    manual_state        varchar(16),
    manual_state_note   varchar(500) NOT NULL DEFAULT '',
    state               varchar(20)  NOT NULL DEFAULT 'open',
    deadline            timestamptz,
    deadline_source     varchar(16),
    manual_deadline     timestamptz,
    member_count        integer      NOT NULL DEFAULT 0,
    open_count          integer      NOT NULL DEFAULT 0,
    in_progress_count   integer      NOT NULL DEFAULT 0,
    fix_applied_count   integer      NOT NULL DEFAULT 0,
    closed_count        integer      NOT NULL DEFAULT 0,
    verified_count      integer      NOT NULL DEFAULT 0,
    related_count       integer      NOT NULL DEFAULT 0,
    risk_points         integer      NOT NULL DEFAULT 0,
    regression_of       uuid,
    archived_at         timestamptz,
    archived_note       varchar(500) NOT NULL DEFAULT '',
    closed_at           timestamptz,
    recomputed_at       timestamptz  NOT NULL DEFAULT now(),
    version             integer      NOT NULL DEFAULT 1,
    created_by          uuid,
    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_tasks PRIMARY KEY (id),
    CONSTRAINT fk_remediation_tasks_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_tasks_action FOREIGN KEY (action_id)
        REFERENCES remediation_actions (id) ON DELETE RESTRICT,
    CONSTRAINT fk_remediation_tasks_campaign FOREIGN KEY (campaign_id)
        REFERENCES remediation_campaigns (id) ON DELETE SET NULL,
    CONSTRAINT fk_remediation_tasks_assignee_user FOREIGN KEY (assignee_user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_remediation_tasks_assignee_group FOREIGN KEY (assignee_group_id)
        REFERENCES groups (id) ON DELETE SET NULL,
    CONSTRAINT fk_remediation_tasks_regression_of FOREIGN KEY (regression_of)
        REFERENCES remediation_tasks (id) ON DELETE SET NULL,
    CONSTRAINT fk_remediation_tasks_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_tasks_manual_state CHECK (manual_state IS NULL OR manual_state IN ('on_hold', 'canceled')),
    CONSTRAINT chk_remediation_tasks_state CHECK (state IN
        ('open', 'in_progress', 'verifying', 'done', 'closed_unverified', 'on_hold', 'canceled', 'archived')),
    CONSTRAINT chk_remediation_tasks_deadline_source CHECK (deadline_source IS NULL OR deadline_source IN ('member', 'manual', 'campaign')),
    CONSTRAINT chk_remediation_tasks_counts CHECK (member_count >= 0 AND open_count >= 0 AND in_progress_count >= 0
        AND fix_applied_count >= 0 AND closed_count >= 0 AND verified_count >= 0 AND related_count >= 0 AND risk_points >= 0),
    CONSTRAINT chk_remediation_tasks_version CHECK (version > 0)
);

COMMENT ON TABLE remediation_tasks IS
    'Who fixes a remediation action and by when: owner, deadline (earliest member SLA) and a state derived from its member findings.';
COMMENT ON COLUMN remediation_tasks.state IS
    'Derived from member finding states (manual only for on_hold/canceled); done needs every member closed and at least one verified fixed.';
COMMENT ON COLUMN remediation_tasks.manual_deadline IS
    'A deadline a person set; the effective deadline is the earliest of it, the open members'' SLA deadlines and the campaign due date, so it can only tighten.';

CREATE INDEX IF NOT EXISTS idx_remediation_tasks_tenant_state
    ON remediation_tasks (tenant_id, state, deadline);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_assignee_user
    ON remediation_tasks (tenant_id, assignee_user_id) WHERE assignee_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_assignee_group
    ON remediation_tasks (tenant_id, assignee_group_id) WHERE assignee_group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_action
    ON remediation_tasks (tenant_id, action_id);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_campaign
    ON remediation_tasks (campaign_id) WHERE campaign_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_regression_of
    ON remediation_tasks (regression_of) WHERE regression_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_recompute
    ON remediation_tasks (recomputed_at) WHERE state NOT IN ('canceled', 'archived');
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_created_by
    ON remediation_tasks (created_by) WHERE created_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS remediation_task_members (
    id           uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id    uuid         NOT NULL,
    task_id      uuid         NOT NULL,
    finding_id   uuid         NOT NULL,
    role         varchar(8)   NOT NULL DEFAULT 'primary',
    join_source  varchar(16)  NOT NULL,
    joined_by    uuid,
    joined_at    timestamptz  NOT NULL DEFAULT now(),
    left_at      timestamptz,
    left_reason  varchar(16),
    left_by      uuid,
    CONSTRAINT pk_remediation_task_members PRIMARY KEY (id),
    CONSTRAINT fk_remediation_task_members_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_members_task FOREIGN KEY (task_id)
        REFERENCES remediation_tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_members_finding FOREIGN KEY (finding_id)
        REFERENCES findings (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_members_joined_by FOREIGN KEY (joined_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_remediation_task_members_left_by FOREIGN KEY (left_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_task_members_role CHECK (role IN ('primary', 'related')),
    CONSTRAINT chk_remediation_task_members_join_source CHECK (join_source IN
        ('manual', 'suggestion', 'auto_join', 'move', 'split', 'merge', 'regression')),
    CONSTRAINT chk_remediation_task_members_left CHECK ((left_at IS NULL) = (left_reason IS NULL)),
    CONSTRAINT chk_remediation_task_members_left_reason CHECK (left_reason IS NULL OR left_reason IN
        ('removed', 'moved', 'split', 'merged', 'regressed', 'detached', 'canceled'))
);

COMMENT ON TABLE remediation_task_members IS
    'Findings of a remediation task, with history: one primary active task per finding, plus related links.';

-- One primary active task per finding (decision: no copies; related links instead).
CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_task_members_primary
    ON remediation_task_members (tenant_id, finding_id) WHERE left_at IS NULL AND role = 'primary';
-- A finding is in a task at most once at a time.
CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_task_members_active
    ON remediation_task_members (task_id, finding_id) WHERE left_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_task_members_task
    ON remediation_task_members (tenant_id, task_id) WHERE left_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_task_members_finding
    ON remediation_task_members (finding_id);
CREATE INDEX IF NOT EXISTS idx_remediation_task_members_joined_by
    ON remediation_task_members (joined_by) WHERE joined_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_task_members_left_by
    ON remediation_task_members (left_by) WHERE left_by IS NOT NULL;

CREATE TABLE IF NOT EXISTS remediation_task_events (
    id          uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid         NOT NULL,
    task_id     uuid         NOT NULL,
    kind        varchar(32)  NOT NULL,
    actor_id    uuid,
    actor_type  varchar(16)  NOT NULL DEFAULT 'user',
    data        jsonb        NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_remediation_task_events PRIMARY KEY (id),
    CONSTRAINT fk_remediation_task_events_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_events_task FOREIGN KEY (task_id)
        REFERENCES remediation_tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_task_events_actor FOREIGN KEY (actor_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_remediation_task_events_actor_type CHECK (actor_type IN ('user', 'system')),
    CONSTRAINT chk_remediation_task_events_data_size CHECK (pg_column_size(data) <= 16384)
);

COMMENT ON TABLE remediation_task_events IS
    'Timeline of a remediation task: one entry per operation (created, members changed, owner, deadline, state).';

CREATE INDEX IF NOT EXISTS idx_remediation_task_events_task
    ON remediation_task_events (tenant_id, task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_task_events_actor
    ON remediation_task_events (actor_id) WHERE actor_id IS NOT NULL;
