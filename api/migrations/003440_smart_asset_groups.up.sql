-- Asset groups that fill themselves (docs/architecture/smart-asset-groups.md).
-- A group's members are its rule matches, plus the assets added by hand or by
-- a pasted list, minus the assets taken out by hand. Members stay stored in
-- asset_group_members so scans, team scope rules, dashboards and reports read
-- them as before; the new source column says how each one came in.

ALTER TABLE asset_group_members
    ADD COLUMN source varchar(10) NOT NULL DEFAULT 'manual',
    ADD CONSTRAINT chk_asset_group_members_source CHECK (source IN ('rule', 'manual', 'paste'));

ALTER TABLE asset_groups
    ADD COLUMN rule jsonb,
    ADD COLUMN rule_editor_id uuid REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN rule_status varchar(16) NOT NULL DEFAULT 'idle',
    ADD COLUMN rule_evaluated_at timestamptz,
    ADD CONSTRAINT chk_asset_groups_rule_object CHECK (rule IS NULL OR jsonb_typeof(rule) = 'object'),
    ADD CONSTRAINT chk_asset_groups_rule_status CHECK (rule_status IN ('idle', 'ok', 'paused', 'over_cap'));

CREATE INDEX idx_asset_groups_rule ON asset_groups (tenant_id) WHERE rule IS NOT NULL;
CREATE INDEX idx_asset_group_members_rule ON asset_group_members (asset_group_id) WHERE source = 'rule';

-- Assets a person took out of a group. They stay out while the rule matches
-- them (excludes win); adding the asset by hand again removes the row.
CREATE TABLE asset_group_exclusions (
    asset_group_id uuid NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    asset_id uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    excluded_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_group_id, asset_id)
);

-- Who joined and left a group, and why.
CREATE TABLE asset_group_member_history (
    id uuid DEFAULT uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_group_id uuid NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    asset_id uuid NOT NULL,
    asset_name varchar(512) NOT NULL DEFAULT '',
    action varchar(8) NOT NULL,
    source varchar(10) NOT NULL,
    reason varchar(40) NOT NULL,
    actor_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_asset_group_member_history_action CHECK (action IN ('joined', 'left')),
    CONSTRAINT chk_asset_group_member_history_source CHECK (source IN ('rule', 'manual', 'paste'))
);

CREATE INDEX idx_asset_group_member_history_group ON asset_group_member_history (asset_group_id, created_at DESC, id DESC);
CREATE INDEX idx_asset_group_member_history_asset ON asset_group_member_history (tenant_id, asset_id, created_at DESC);
