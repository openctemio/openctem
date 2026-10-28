-- Restore the six ai_triage.* sub-module rows exactly as 003403 wrote them.
-- Tenant overrides (tenant_modules rows) and the original module_id of moved
-- permissions/event types are NOT restored: the sub-modules did nothing, so
-- no behaviour depended on them.
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)
VALUES
    ('ai_triage.bulk', 'ai_triage_bulk', 'Bulk Triage', 'Bulk triage operations', 'Layers', 'prioritization', 1, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.auto', 'ai_triage_auto', 'Auto Triage', 'Auto-triage on finding creation', 'Zap', 'prioritization', 2, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.workflow', 'ai_triage_workflow', 'Workflow Triage', 'Workflow triggers and actions', 'GitPullRequest', 'prioritization', 3, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.byok', 'ai_triage_byok', 'BYOK Mode', 'Bring Your Own Key mode', 'Key', 'prioritization', 4, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.agent', 'ai_triage_agent', 'Agent Mode', 'Self-hosted Agent mode', 'Cpu', 'prioritization', 5, TRUE, false, 'released', 'ai_triage'),
    ('ai_triage.custom_prompts', 'ai_triage_custom_prompts', 'Custom Prompts', 'Custom prompt templates', 'FileText', 'prioritization', 6, TRUE, false, 'released', 'ai_triage')
ON CONFLICT (id) DO NOTHING;

UPDATE modules SET description = 'AI-powered vulnerability triage (Bulk, Auto, Workflow, BYOK, Agent modes)' WHERE id = 'ai_triage';
