-- Put the Quick Scan Template back in the active list.
UPDATE scan_workflows
SET is_active = true, updated_at = now()
WHERE id = '00000000-0000-0000-0000-000000000001' AND is_system_template AND NOT is_active;
