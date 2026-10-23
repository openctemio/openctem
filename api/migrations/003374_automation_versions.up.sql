-- Automation versions and modes (RFC-125 §5).
--
-- The nodes and edges of an automation are its draft. Publishing stores the
-- draft as an immutable row of automation_versions; a live automation runs its
-- published version, a simulate automation runs its draft and only records
-- what it would do. New automations start in simulate.
--
-- Existing automations that are switched on keep acting: each becomes version
-- 1, published by its owner, mode live. Automations that are off stay in
-- simulate without a version (switching one on runs it in simulate until it is
-- published).
--
-- Run steps keep the node id of the definition they ran. The foreign key to
-- automation_nodes is dropped: a live run executes a version's nodes, which
-- the draft may have replaced, and replacing the draft no longer deletes the
-- step history of earlier runs (the old ON DELETE CASCADE did).

CREATE TABLE automation_versions (
    id            UUID         NOT NULL DEFAULT uuid_generate_v7() PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    automation_id UUID         NOT NULL REFERENCES automations (id) ON DELETE CASCADE,
    version       INTEGER      NOT NULL CHECK (version > 0),
    definition    JSONB        NOT NULL,
    digest        VARCHAR(64)  NOT NULL,
    risk_class    VARCHAR(10)  NOT NULL CHECK (risk_class IN ('low', 'elevated', 'high')),
    status        VARCHAR(20)  NOT NULL CHECK (status IN ('published', 'pending_approval', 'superseded', 'retired')),
    published_by  UUID         REFERENCES users (id) ON DELETE SET NULL,
    published_at  TIMESTAMPTZ,
    approved_by   UUID         REFERENCES users (id) ON DELETE SET NULL,
    approved_at   TIMESTAMPTZ,
    step_up_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_automation_versions_number UNIQUE (automation_id, version)
);

CREATE INDEX idx_automation_versions_tenant ON automation_versions (tenant_id, automation_id, version DESC);
-- At most one published version per automation.
CREATE UNIQUE INDEX uq_automation_versions_published ON automation_versions (automation_id) WHERE status = 'published';

COMMENT ON TABLE automation_versions IS 'Immutable published definitions of an automation; live runs execute the published one';
COMMENT ON COLUMN automation_versions.digest IS 'SHA-256 of the definition (Definition.Digest); an approval binds it. The literal backfill marks a row migrated from an old graph until the API recomputes it';

ALTER TABLE automations
    ADD COLUMN mode VARCHAR(10) NOT NULL DEFAULT 'simulate',
    ADD COLUMN published_version_id UUID REFERENCES automation_versions (id) ON DELETE SET NULL,
    ADD CONSTRAINT chk_automations_mode CHECK (mode IN ('simulate', 'live')) NOT VALID;

COMMENT ON COLUMN automations.mode IS 'live: runs execute the published version; simulate: runs execute the draft and only record what they would do';

-- Existing runs all acted: they are live. New runs always name their mode.
ALTER TABLE automation_runs
    ADD COLUMN mode VARCHAR(10) NOT NULL DEFAULT 'live',
    ADD COLUMN version_id UUID REFERENCES automation_versions (id) ON DELETE SET NULL,
    ADD CONSTRAINT chk_automation_runs_mode CHECK (mode IN ('simulate', 'live')) NOT VALID;
-- The check is validated by the next migration (automation_versions_validate),
-- so this one never scans the whole runs table under its lock.
CREATE INDEX idx_automation_runs_version ON automation_runs (version_id) WHERE version_id IS NOT NULL;
ALTER TABLE automation_runs ALTER COLUMN mode SET DEFAULT 'simulate';

ALTER TABLE automation_run_steps DROP CONSTRAINT IF EXISTS automation_run_steps_node_id_fkey;

-- Version 1 of every automation that is switched on, from its current graph.
INSERT INTO automation_versions (tenant_id, automation_id, version, definition, digest, risk_class, status, published_by, published_at)
SELECT a.tenant_id, a.id, 1, d.definition,
       -- Placeholder: the API computes the canonical digest (Definition.Digest in
       -- Go) for these rows at startup; SQL cannot reproduce that encoding.
       'backfill',
       CASE
           WHEN EXISTS (SELECT 1 FROM automation_nodes n WHERE n.automation_id = a.id
                         AND (n.config->>'action_type' NOT IN ('add_tags', 'remove_tags', 'assign_user', 'update_status',
                                                               'create_ticket', 'update_ticket', 'trigger_ai_triage')
                              OR (n.config->'trigger_config'->>'allow_automation_triggers') = 'true'))
               THEN 'high'
           WHEN EXISTS (SELECT 1 FROM automation_nodes n WHERE n.automation_id = a.id
                         AND (n.config->>'action_type' IN ('assign_user', 'update_status', 'create_ticket', 'update_ticket', 'trigger_ai_triage')
                              OR COALESCE(n.config->>'notification_type', '') <> ''))
               THEN 'elevated'
           ELSE 'low'
       END,
       'published', a.created_by, now()
  FROM automations a
 CROSS JOIN LATERAL (
       SELECT jsonb_build_object(
                  'nodes', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                          'id', n.id, 'node_key', n.node_key, 'node_type', n.node_type,
                                          'name', n.name, 'description', COALESCE(n.description, ''),
                                          'ui_position', jsonb_build_object('x', n.ui_position_x, 'y', n.ui_position_y),
                                          'config', n.config) ORDER BY n.node_key)
                                       FROM automation_nodes n WHERE n.automation_id = a.id), '[]'::jsonb),
                  'edges', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                          'source_node_key', e.source_node_key, 'target_node_key', e.target_node_key,
                                          'source_handle', COALESCE(e.source_handle, ''), 'label', COALESCE(e.label, ''))
                                          ORDER BY e.source_node_key, e.target_node_key, e.source_handle)
                                       FROM automation_edges e WHERE e.automation_id = a.id), '[]'::jsonb)
              ) AS definition
       ) d
 WHERE a.is_active;

UPDATE automations a
   SET mode = 'live',
       published_version_id = v.id
  FROM automation_versions v
 WHERE v.automation_id = a.id
   AND v.version = 1
   AND v.status = 'published';

-- Row-level security policy in shadow mode, like the other tenant tables.
DROP POLICY IF EXISTS automation_versions_tenant_isolation ON automation_versions;
CREATE POLICY automation_versions_tenant_isolation ON automation_versions
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
