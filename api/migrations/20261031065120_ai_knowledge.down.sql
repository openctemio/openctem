DROP TABLE IF EXISTS ai_run_knowledge;
ALTER TABLE ai_runs
    DROP CONSTRAINT IF EXISTS chk_ai_runs_retrieval,
    DROP COLUMN IF EXISTS retrieval_index,
    DROP COLUMN IF EXISTS retrieval_mode;
DROP TABLE IF EXISTS ai_knowledge_chunks;
DROP TABLE IF EXISTS ai_knowledge_documents;
DROP TRIGGER IF EXISTS trigger_refuse_foreign_ai_knowledge_team ON ai_knowledge_source_teams;
DROP TABLE IF EXISTS ai_knowledge_source_teams;
DROP FUNCTION IF EXISTS refuse_foreign_ai_knowledge_team();
DROP TABLE IF EXISTS ai_knowledge_sources;
DELETE FROM role_permissions WHERE permission_id IN ('ai_knowledge:read', 'ai_knowledge:manage');
DELETE FROM permissions WHERE id IN ('ai_knowledge:read', 'ai_knowledge:manage');
