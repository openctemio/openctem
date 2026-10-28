-- Removes the AI governance tables. ai_triage_results is untouched by the up
-- step (it stays the source until the contract step), so nothing is lost
-- that the previous release reads. The two timeline entry types stay allowed
-- (rows may use them).
DROP TABLE IF EXISTS ai_suggestions;
DROP TABLE IF EXISTS ai_runs;
DROP TABLE IF EXISTS tenant_ai_use_cases;
