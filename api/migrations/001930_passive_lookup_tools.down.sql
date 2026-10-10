-- Removes the passive lookup steps and tool rows this migration added.
UPDATE scan_workflows
SET description = 'Find the subdomains of your root domains from passive sources (certificate transparency, passive DNS) and resolve them through recursive resolvers. Nothing is sent to your hosts (T0). New names go to the review queue.',
    version = 1
WHERE id = 'a0000002-0000-0000-0000-000000000006' AND version = 2;

DELETE FROM scan_workflow_steps WHERE id IN ('b0000002-0006-0000-0000-000000000003', 'b0000002-0006-0000-0000-000000000004');

DELETE FROM tools WHERE id IN ('00000000-0000-0000-0000-000000000132', '00000000-0000-0000-0000-000000000133');
