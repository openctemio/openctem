-- Restores the legacy system templates' steps and descriptions as they were.

DELETE FROM scan_workflow_steps s
USING scan_workflows w
WHERE w.id = s.scan_workflow_id
  AND w.is_system_template AND w.id::text LIKE 'a0000001-%';

INSERT INTO scan_workflow_steps SELECT * FROM legacy_template_steps_backup_001322;

UPDATE scan_workflows w SET description = b.description
FROM legacy_templates_backup_001322 b
WHERE b.id = w.id;

DROP TABLE legacy_template_steps_backup_001322;
DROP TABLE legacy_templates_backup_001322;
