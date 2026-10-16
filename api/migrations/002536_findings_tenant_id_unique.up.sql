-- A unique (tenant_id, id) index on findings, so tables that point at a
-- finding can use a composite (tenant_id, finding_id) foreign key: a row can
-- then never link a finding of another tenant, whatever the code does
-- (docs/rfcs/RFC-098-remediation-tasks.md, first users: remediation task
-- members). id is the primary key, so the index holds no duplicate.
--
-- CONCURRENTLY keeps the large table writable while the index builds; it
-- cannot run in a transaction, so this file holds exactly one statement.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_findings_tenant_id_id ON findings (tenant_id, id);
