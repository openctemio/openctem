-- Revert 000241: gitleaks is the secret scanner again. Every betterleaks
-- reference moves back to gitleaks (including findings first reported by
-- betterleaks: the code this reverts to knows only gitleaks), then the
-- betterleaks tool row is removed.

UPDATE tools
SET is_active   = TRUE,
    description = 'Secret detection in git repositories',
    metadata    = COALESCE(metadata, '{}'::jsonb) - 'replaced_by',
    updated_at  = NOW()
WHERE name = 'gitleaks' AND tenant_id IS NULL;

UPDATE findings f
SET tool_name = 'gitleaks',
    tool_id   = CASE WHEN f.tool_id = bl.id THEN gl.id ELSE f.tool_id END
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND f.tool_name = 'betterleaks';

UPDATE scanner_templates t SET template_type = 'gitleaks', updated_at = NOW()
WHERE template_type = 'betterleaks'
  AND NOT EXISTS (SELECT 1 FROM scanner_templates x
                  WHERE x.tenant_id = t.tenant_id AND x.template_type = 'gitleaks' AND x.name = t.name);
DELETE FROM scanner_templates WHERE template_type = 'betterleaks';
UPDATE template_sources SET template_type = 'gitleaks', updated_at = NOW()
WHERE template_type = 'betterleaks';

ALTER TABLE scanner_templates DROP CONSTRAINT IF EXISTS chk_scanner_template_type;
ALTER TABLE scanner_templates ADD CONSTRAINT chk_scanner_template_type
    CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks'));
ALTER TABLE template_sources DROP CONSTRAINT IF EXISTS chk_template_type;
ALTER TABLE template_sources ADD CONSTRAINT chk_template_type
    CHECK (template_type IN ('nuclei', 'semgrep', 'gitleaks'));

UPDATE suppression_rules SET tool_name = 'gitleaks', updated_at = NOW()
WHERE tool_name = 'betterleaks';

UPDATE workflow_nodes
SET config = jsonb_set(config, '{trigger_config,tool_filter}',
                       (SELECT jsonb_agg(DISTINCT CASE WHEN e = to_jsonb('betterleaks'::text)
                                                       THEN to_jsonb('gitleaks'::text) ELSE e END)
                        FROM jsonb_array_elements(config -> 'trigger_config' -> 'tool_filter') AS e))
WHERE jsonb_typeof(config -> 'trigger_config' -> 'tool_filter') = 'array'
  AND config -> 'trigger_config' -> 'tool_filter' @> '["betterleaks"]'::jsonb;

UPDATE sensors
SET tools = (SELECT array_agg(DISTINCT CASE WHEN t = 'betterleaks' THEN 'gitleaks' ELSE t END)
             FROM unnest(tools) AS t)
WHERE 'betterleaks' = ANY(tools);

UPDATE scan_schedules
SET scanner_configs = (scanner_configs - 'betterleaks')
                      || jsonb_build_object('gitleaks', scanner_configs -> 'betterleaks')
WHERE scanner_configs ? 'betterleaks' AND NOT scanner_configs ? 'gitleaks';
UPDATE scan_schedules SET scanner_configs = scanner_configs - 'betterleaks'
WHERE scanner_configs ? 'betterleaks';

UPDATE scan_profiles
SET tools_config = (tools_config - 'betterleaks')
                   || jsonb_build_object('gitleaks', tools_config -> 'betterleaks'),
    updated_at = NOW()
WHERE tools_config ? 'betterleaks' AND NOT tools_config ? 'gitleaks';
UPDATE scan_profiles SET tools_config = tools_config - 'betterleaks', updated_at = NOW()
WHERE tools_config ? 'betterleaks';

UPDATE scans SET scanner_name = 'gitleaks', updated_at = NOW()
WHERE scanner_name = 'betterleaks';

UPDATE pipeline_steps p
SET tool = 'gitleaks',
    tool_id = CASE WHEN p.tool_id = bl.id THEN gl.id ELSE p.tool_id END
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND (p.tool = 'betterleaks' OR p.tool_id = bl.id);

-- Tool-id references: move back, then drop what cannot move (a duplicate).
UPDATE tenant_tool_configs c SET tool_id = gl.id, updated_at = NOW()
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND c.tool_id = bl.id
  AND NOT EXISTS (SELECT 1 FROM tenant_tool_configs x WHERE x.tenant_id = c.tenant_id AND x.tool_id = gl.id);
UPDATE rule_sources s SET tool_id = gl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND s.tool_id = bl.id
  AND NOT EXISTS (SELECT 1 FROM rule_sources x
                  WHERE x.tenant_id = s.tenant_id AND x.tool_id = gl.id AND x.name = s.name);
UPDATE rules r SET tool_id = gl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND r.tool_id = bl.id;
UPDATE rule_overrides o SET tool_id = gl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND o.tool_id = bl.id
  AND NOT EXISTS (SELECT 1 FROM rule_overrides x
                  WHERE x.tenant_id = o.tenant_id AND x.tool_id = gl.id
                    AND x.rule_pattern = o.rule_pattern
                    AND x.asset_group_id IS NOT DISTINCT FROM o.asset_group_id
                    AND x.scan_profile_id IS NOT DISTINCT FROM o.scan_profile_id);
UPDATE rule_bundles b SET tool_id = gl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND b.tool_id = bl.id;
UPDATE tool_executions e SET tool_id = gl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND e.tool_id = bl.id;

UPDATE modules SET description = replace(replace(description, 'Betterleaks', 'Gitleaks'), 'betterleaks', 'gitleaks')
WHERE description ILIKE '%betterleaks%';

DELETE FROM tools WHERE name = 'betterleaks' AND tenant_id IS NULL;
