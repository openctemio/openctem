-- Rollback for 000163_ai_triage_budgets.up.sql
--
-- Safe because the BudgetService fails-open when the table is missing
-- (Phase 1 ships with the feature flag off, so no code path relies
-- on this table existing yet).

DROP INDEX IF EXISTS idx_ai_triage_budgets_tenant_period;
DROP TABLE IF EXISTS ai_triage_budgets;
