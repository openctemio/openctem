-- Lineage of a tenant's copy of a system scan workflow (template updates;
-- docs/architecture/scan-stages.md#starter-workflows). source_template_id is
-- the system template the copy was made from; source_spec is that
-- template's settings and steps as the copy last took them (at copy time,
-- or when a template update was applied or dismissed). A changed system
-- template is offered to the copy as an update; the copy is never changed
-- without a person applying it.
--
-- Backfill: copies made before this migration get their source from the
-- audit event of the copy (metadata source_template_id, same tenant), or,
-- without one, from a system template whose name the copy has ("Network" or
-- "Network (Copy)") when they share a step key. source_spec stays NULL:
-- the copy's own steps are then the base of the comparison.
--
-- Live impact: two nullable columns (no rewrite) and one UPDATE of tenant
-- copies of system templates (a handful of rows).

ALTER TABLE scan_workflows
    ADD COLUMN IF NOT EXISTS source_template_id uuid,
    ADD COLUMN IF NOT EXISTS source_spec jsonb;

COMMENT ON COLUMN scan_workflows.source_template_id IS
    'The system template this tenant copy was made from (template updates).';
COMMENT ON COLUMN scan_workflows.source_spec IS
    'The system template''s settings and steps as this copy last took them; NULL: the copy''s own steps.';

UPDATE scan_workflows w
   SET source_template_id = src.id
  FROM (
        SELECT DISTINCT ON (a.resource_id) a.resource_id, a.tenant_id, a.metadata->>'source_template_id' AS source
          FROM audit_logs a
         WHERE a.action = 'scan_workflow.created'
           AND a.resource_type = 'scan_workflow'
           AND a.metadata ? 'source_template_id'
         ORDER BY a.resource_id, a.logged_at DESC
       ) l
  JOIN scan_workflows src ON src.id::text = l.source AND src.is_system_template
 WHERE w.id::text = l.resource_id
   AND w.tenant_id = l.tenant_id
   AND NOT w.is_system_template
   AND w.source_template_id IS NULL;

UPDATE scan_workflows w
   SET source_template_id = src.id
  FROM scan_workflows src
 WHERE src.is_system_template
   AND NOT w.is_system_template
   AND w.source_template_id IS NULL
   AND w.retired_at IS NULL
   AND (w.name = src.name OR w.name = src.name || ' (Copy)')
   AND EXISTS (SELECT 1
                 FROM scan_workflow_steps ws
                 JOIN scan_workflow_steps ss ON ss.step_key = ws.step_key AND ss.scan_workflow_id = src.id
                WHERE ws.scan_workflow_id = w.id);

CREATE INDEX IF NOT EXISTS idx_scan_workflows_source_template
    ON scan_workflows (tenant_id, source_template_id) WHERE source_template_id IS NOT NULL;
