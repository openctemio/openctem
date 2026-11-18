-- ci_trust_new_repositories: for a CI trust configuration that admits every
-- project of a self-managed GitLab (rules.all_repositories), the projects
-- seen for the first time and waiting for an administrator (pending), and
-- the projects or groups an administrator blocked. Approved projects and
-- groups are not kept here: they join the configuration's repositories or
-- owners (an approved project keeps its row, state approved, with the ids
-- it was seen with). At most 25 pending rows per top-level group and 500 per
-- configuration (the API refuses the rest without recording them).
CREATE TABLE IF NOT EXISTS ci_trust_new_repositories (
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_id  UUID        NOT NULL REFERENCES ci_trust_configs(id) ON DELETE CASCADE,
    -- project: a full project path (lower case); group: a top-level group.
    kind       TEXT        NOT NULL CHECK (kind IN ('project', 'group')),
    name       TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 500),
    -- The top-level group of a project (its first path segment).
    group_name TEXT        NOT NULL CHECK (char_length(group_name) BETWEEN 1 AND 255),
    -- approved: a project an administrator approved, kept (not listed) so
    -- its first admitted run must carry the project id that was seen.
    state      TEXT        NOT NULL CHECK (state IN ('pending', 'blocked', 'approved')),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    count      BIGINT      NOT NULL DEFAULT 1 CHECK (count >= 0),
    decided_by TEXT        NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ,
    -- Verified claims of the first sighting of a project (GitLab project_id,
    -- namespace_path, namespace_id); empty for a group or a block.
    project_id     TEXT NOT NULL DEFAULT '' CHECK (char_length(project_id) <= 64),
    namespace_path TEXT NOT NULL DEFAULT '' CHECK (char_length(namespace_path) <= 500),
    namespace_id   TEXT NOT NULL DEFAULT '' CHECK (char_length(namespace_id) <= 64),
    PRIMARY KEY (config_id, kind, name)
);

CREATE INDEX IF NOT EXISTS idx_ci_trust_new_repositories_tenant
    ON ci_trust_new_repositories (tenant_id, config_id, state, group_name);

COMMENT ON TABLE ci_trust_new_repositories IS
    'Pending and blocked projects or groups of an all-projects CI trust configuration (approved ones join the configuration).';

-- Notice when a project of a group not seen before asks (optional per
-- configuration, notify_new_groups).
INSERT INTO event_types (id, name, description, category, module_id, is_active, metadata, created_at)
VALUES ('ci.new_repository_group', 'CI new group asks', 'A project of a GitLab group not seen before asks to send CI results (all-projects trust)', 'sensor', 'scans', true, '{}', NOW())
ON CONFLICT (id) DO NOTHING;
