-- AI triage organization consent (docs/architecture/ai-triage.md).
--
-- From this release no finding content is sent to an AI provider until an
-- organization administrator turns AI triage on (Settings > AI), recorded as
-- settings.ai.enabled_at / enabled_by. An organization that already used AI
-- triage keeps it on: each organization with at least one AI triage result,
-- and whose AI mode is not "disabled", is marked opted in by the upgrade
-- (enabled_by = 'upgrade') and gets one audit row saying so. Every other
-- organization is off until an administrator turns it on.
--
-- Live impact: one UPDATE of the organizations that have ai_triage_results
-- rows (DISTINCT over ai_triage_results, indexed by tenant), one audit row
-- each. Run twice, it changes nothing the second time.

WITH used AS (
    SELECT DISTINCT tenant_id FROM ai_triage_results
), opted AS (
    UPDATE tenants t
       SET settings = jsonb_set(
               t.settings,
               '{ai}',
               COALESCE(t.settings->'ai', '{}'::jsonb) || jsonb_build_object(
                   'enabled_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   'enabled_by', 'upgrade'),
               true),
           updated_at = now()
      FROM used u
     WHERE t.id = u.tenant_id
       AND t.settings->'ai'->>'enabled_at' IS NULL
       AND COALESCE(t.settings->'ai'->>'mode', 'platform') <> 'disabled'
    RETURNING t.id
)
INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, severity, message, metadata)
SELECT o.id, 'ai_settings.opt_in_migrated', 'tenant', o.id::text, 'high',
       'AI triage stays on: the organization used it before organization consent was introduced. '
       || 'An administrator can turn it off in Settings > AI.',
       jsonb_build_object('source', 'migration')
  FROM opted o;
