DROP TRIGGER IF EXISTS trg_findings_vex_statement_scope ON findings;
DROP FUNCTION IF EXISTS findings_vex_statement_scope_check();
DROP INDEX IF EXISTS idx_findings_vex_statement;
ALTER TABLE findings DROP COLUMN IF EXISTS vex_statement_id;
DROP TRIGGER IF EXISTS trg_vex_statements_scope ON vex_statements;
DROP FUNCTION IF EXISTS vex_statements_scope_check();
DROP TABLE IF EXISTS vex_statements;
