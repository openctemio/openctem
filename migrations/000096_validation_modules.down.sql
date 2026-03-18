DELETE FROM tenant_modules WHERE module_id IN ('attack_simulation', 'control_testing');
DELETE FROM modules WHERE id IN ('attack_simulation', 'control_testing');
