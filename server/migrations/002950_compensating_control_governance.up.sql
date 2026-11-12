-- Compensating control governance (backend audit B7-R2).
--
-- 1. The built-in Member role loses ctem:compensating_controls:write: an
--    effective control lowers the priority and SLA of every finding on the
--    assets it covers, so creating, testing or linking one is for owners,
--    admins and roles granted it explicitly (the program-lead template).
-- 2. The rule for an effective control changed in code (tested pass, review
--    date not passed, reduction of at least 0.25, and a control lowers a
--    class by at most one level). Every asset a control covers is queued
--    once so its findings are recomputed under that rule; the asset risk
--    score is queued as well.

DELETE FROM role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000003'
  AND permission_id = 'ctem:compensating_controls:write';

INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
SELECT DISTINCT a.id, a.tenant_id, 'control_change'
FROM compensating_control_assets cca
JOIN assets a ON a.id = cca.asset_id AND a.deleted_at IS NULL
ORDER BY a.id
ON CONFLICT (asset_id) DO NOTHING;

INSERT INTO asset_risk_queue (asset_id, tenant_id)
SELECT DISTINCT a.id, a.tenant_id
FROM compensating_control_assets cca
JOIN assets a ON a.id = cca.asset_id AND a.deleted_at IS NULL
ORDER BY a.id
ON CONFLICT (asset_id) DO NOTHING;
