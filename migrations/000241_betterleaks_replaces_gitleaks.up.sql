-- Betterleaks replaces gitleaks as the secret scanner.
--
-- Betterleaks (https://github.com/betterleaks/betterleaks) is gitleaks'
-- successor by its original author; v1 keeps the gitleaks config format and
-- JSON report, so a secret both tools report keeps its fingerprint
-- (asset + path + rule + line + masked value; the tool name is not part of it).
--
-- Add-only: the gitleaks tool row stays (inactive) so history that points at
-- it (tool_executions, scan_sessions, ingest_reports, assets.discovery_tool)
-- keeps its meaning. Everything that CONFIGURES or IDENTIFIES the secret
-- scanner moves to betterleaks:
--   * the tool registry, its capabilities, tenant configs and rule sets;
--   * scans, scan profiles, scope schedules, pipeline steps, sensors' tools,
--     workflow trigger filters, suppression rules, scanner templates;
--   * findings.tool_name. Auto-resolve and suppression match the tool name
--     exactly, and the ingest upsert never rewrites tool_name, so findings
--     left as 'gitleaks' would never be auto-resolved by a betterleaks scan.
--     Renaming them keeps every existing finding matched across the switch;
--     its fingerprint is unchanged, so the next scan updates it in place.
-- From here on the API maps a 'gitleaks' report from an older sensor to
-- 'betterleaks' at ingest (pkg/domain/tool.CanonicalName), the platform's
-- one mapping point. Every statement is idempotent.

-- 1. Tool registry -----------------------------------------------------------
INSERT INTO tools (id, name, display_name, description, category_id, install_method,
                   version_cmd, capabilities, supported_targets, output_formats,
                   docs_url, github_url, is_active, is_builtin, tags, metadata)
SELECT '00000000-0000-0000-0000-000000000111', 'betterleaks', 'Betterleaks',
       'Secret detection in code, git history and archives (successor to gitleaks)',
       COALESCE((SELECT category_id FROM tools WHERE name = 'gitleaks' AND tenant_id IS NULL),
                (SELECT id FROM tool_categories WHERE name = 'secrets' AND tenant_id IS NULL)),
       'binary', 'betterleaks version',
       ARRAY['secrets'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'],
       'https://github.com/betterleaks/betterleaks#readme',
       'https://github.com/betterleaks/betterleaks',
       TRUE, TRUE, ARRAY['secrets'], '{"replaces": "gitleaks"}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'betterleaks' AND tenant_id IS NULL);

INSERT INTO tool_capabilities (tool_id, capability_id)
SELECT bl.id, tc.capability_id
FROM tools bl
JOIN tools gl ON gl.name = 'gitleaks' AND gl.tenant_id IS NULL
JOIN tool_capabilities tc ON tc.tool_id = gl.id
WHERE bl.name = 'betterleaks' AND bl.tenant_id IS NULL
ON CONFLICT (tool_id, capability_id) DO NOTHING;

UPDATE tools
SET is_active   = FALSE,
    description = 'Replaced by Betterleaks (its successor). Kept for scan history.',
    metadata    = COALESCE(metadata, '{}'::jsonb) || '{"replaced_by": "betterleaks"}'::jsonb,
    updated_at  = NOW()
WHERE name = 'gitleaks' AND tenant_id IS NULL AND is_active;

-- 2. Tool-id references (configuration, not history) ------------------------
-- gl/bl: the platform gitleaks and betterleaks rows.
UPDATE tenant_tool_configs c
SET tool_id = bl.id, updated_at = NOW()
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND c.tool_id = gl.id
  AND NOT EXISTS (SELECT 1 FROM tenant_tool_configs x WHERE x.tenant_id = c.tenant_id AND x.tool_id = bl.id);

UPDATE rule_sources s SET tool_id = bl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND s.tool_id = gl.id
  AND NOT EXISTS (SELECT 1 FROM rule_sources x
                  WHERE x.tenant_id = s.tenant_id AND x.tool_id = bl.id AND x.name = s.name);

UPDATE rules r SET tool_id = bl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND r.tool_id = gl.id;

UPDATE rule_overrides o SET tool_id = bl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND o.tool_id = gl.id
  AND NOT EXISTS (SELECT 1 FROM rule_overrides x
                  WHERE x.tenant_id = o.tenant_id AND x.tool_id = bl.id
                    AND x.rule_pattern = o.rule_pattern
                    AND x.asset_group_id IS NOT DISTINCT FROM o.asset_group_id
                    AND x.scan_profile_id IS NOT DISTINCT FROM o.scan_profile_id);

UPDATE rule_bundles b SET tool_id = bl.id
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND b.tool_id = gl.id;

UPDATE pipeline_steps p
SET tool = 'betterleaks',
    tool_id = CASE WHEN p.tool_id = gl.id OR p.tool_id IS NULL THEN bl.id ELSE p.tool_id END
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND (lower(p.tool) = 'gitleaks' OR p.tool_id = gl.id);

-- 3. Scanner names in configuration -----------------------------------------
UPDATE scans SET scanner_name = 'betterleaks', updated_at = NOW()
WHERE lower(scanner_name) = 'gitleaks';

-- JSON objects keyed by tool name: move the key, keep its settings. A key
-- that already exists under 'betterleaks' wins (it was set deliberately).
UPDATE scan_profiles
SET tools_config = (tools_config - 'gitleaks')
                   || jsonb_build_object('betterleaks', tools_config -> 'gitleaks'),
    updated_at = NOW()
WHERE tools_config ? 'gitleaks' AND NOT tools_config ? 'betterleaks';

UPDATE scan_profiles SET tools_config = tools_config - 'gitleaks', updated_at = NOW()
WHERE tools_config ? 'gitleaks';

UPDATE scan_schedules
SET scanner_configs = (scanner_configs - 'gitleaks')
                      || jsonb_build_object('betterleaks', scanner_configs -> 'gitleaks')
WHERE scanner_configs ? 'gitleaks' AND NOT scanner_configs ? 'betterleaks';

UPDATE scan_schedules SET scanner_configs = scanner_configs - 'gitleaks'
WHERE scanner_configs ? 'gitleaks';

-- Sensors: the tools an admin assigned to each sensor drive dispatch.
UPDATE sensors
SET tools = (SELECT array_agg(DISTINCT CASE WHEN lower(t) = 'gitleaks' THEN 'betterleaks' ELSE t END)
             FROM unnest(tools) AS t)
WHERE EXISTS (SELECT 1 FROM unnest(tools) AS t WHERE lower(t) = 'gitleaks');

-- Workflow triggers filtering on the finding's tool.
UPDATE workflow_nodes
SET config = jsonb_set(config, '{trigger_config,tool_filter}',
                       (SELECT jsonb_agg(DISTINCT CASE WHEN e = to_jsonb('gitleaks'::text)
                                                       THEN to_jsonb('betterleaks'::text) ELSE e END)
                        FROM jsonb_array_elements(config -> 'trigger_config' -> 'tool_filter') AS e))
WHERE jsonb_typeof(config -> 'trigger_config' -> 'tool_filter') = 'array'
  AND config -> 'trigger_config' -> 'tool_filter' @> '["gitleaks"]'::jsonb;

-- Suppression rules match the finding's tool name.
UPDATE suppression_rules SET tool_name = 'betterleaks', updated_at = NOW()
WHERE lower(tool_name) = 'gitleaks';

-- 4. Scanner templates: betterleaks reads gitleaks-format TOML rules. The
-- CHECK keeps 'gitleaks' allowed so API pods of the previous release can
-- still write during a rolling deploy; nothing in this release writes it.
ALTER TABLE scanner_templates DROP CONSTRAINT IF EXISTS chk_scanner_template_type;
ALTER TABLE scanner_templates ADD CONSTRAINT chk_scanner_template_type
    CHECK (template_type IN ('nuclei', 'semgrep', 'betterleaks', 'gitleaks'));
ALTER TABLE template_sources DROP CONSTRAINT IF EXISTS chk_template_type;
ALTER TABLE template_sources ADD CONSTRAINT chk_template_type
    CHECK (template_type IN ('nuclei', 'semgrep', 'betterleaks', 'gitleaks'));

UPDATE scanner_templates t SET template_type = 'betterleaks', updated_at = NOW()
WHERE template_type = 'gitleaks'
  AND NOT EXISTS (SELECT 1 FROM scanner_templates x
                  WHERE x.tenant_id = t.tenant_id AND x.template_type = 'betterleaks' AND x.name = t.name);

UPDATE template_sources SET template_type = 'betterleaks', updated_at = NOW()
WHERE template_type = 'gitleaks';

-- 5. Findings ------------------------------------------------------------------
UPDATE findings f
SET tool_name = 'betterleaks',
    tool_id   = CASE WHEN f.tool_id = gl.id THEN bl.id ELSE f.tool_id END
FROM tools gl, tools bl
WHERE gl.name = 'gitleaks' AND gl.tenant_id IS NULL
  AND bl.name = 'betterleaks' AND bl.tenant_id IS NULL
  AND lower(f.tool_name) = 'gitleaks';

-- 6. Module catalogue copy ----------------------------------------------------------
UPDATE modules SET description = replace(replace(description, 'Gitleaks', 'Betterleaks'), 'gitleaks', 'betterleaks')
WHERE description ILIKE '%gitleaks%';
