DELETE FROM event_types WHERE id IN ('compliance_assessment_updated', 'compliance_control_overdue');
DELETE FROM role_permissions WHERE permission_id LIKE 'compliance:%';
DELETE FROM permissions WHERE id LIKE 'compliance:%';
DELETE FROM modules WHERE id = 'compliance';
