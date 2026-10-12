-- Remove the starter workflows (their steps cascade) and reactivate the presets
-- they replaced (the two web/API presets were inactive before).

DELETE FROM pipeline_templates WHERE is_system_template AND id IN ('a0000002-0000-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000005');

UPDATE pipeline_templates SET is_active = true
WHERE is_system_template AND id IN ('a0000001-0000-0000-0000-000000000001', 'a0000001-0000-0000-0000-000000000002', 'a0000001-0000-0000-0000-000000000003', 'a0000001-0000-0000-0000-000000000006');
