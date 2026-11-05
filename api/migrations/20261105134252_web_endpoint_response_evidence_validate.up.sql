-- Validates the two CHECK constraints web_endpoint_response_evidence added NOT
-- VALID (docs/rfcs/RFC-056-web-attack-surface.md, amendment 2026-11-05).
--
-- VALIDATE CONSTRAINT reads the table under a lock that lets reads and writes
-- continue (SHARE UPDATE EXCLUSIVE); it runs in its own transaction so the
-- ACCESS EXCLUSIVE lock of the ALTER TABLE that added the constraints is
-- already gone. The lock timeout fails the migration instead of queueing
-- behind a long-running vacuum or other DDL on the table.
--
-- Live impact: a read of web_endpoints, no write blocked. Both columns are
-- new and NULL in every existing row, so the checks hold.

SET LOCAL lock_timeout = '5s';

ALTER TABLE web_endpoints VALIDATE CONSTRAINT chk_web_endpoints_resp_size;
ALTER TABLE web_endpoints VALIDATE CONSTRAINT chk_web_endpoints_resp_hash;
