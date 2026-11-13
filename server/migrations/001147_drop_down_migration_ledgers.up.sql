-- Drop the two tables that only fed down migrations (RFC-053, migration
-- baseline). priority_rule_safety_report (000942) and
-- role_permissions_admin_only_stripped (000945) recorded what those
-- migrations changed so their down migrations could undo it. The baseline
-- replaced 000942 and 000945, down migrations included, and no code reads
-- either table. A fresh database never has them (the baseline leaves them
-- out), so this is a no-op there; an existing database loses the two
-- records, which the pre-upgrade backup keeps.
--
-- expand-contract-ok: contract step; nothing reads these tables (their only reader, the down migrations, is gone)
DROP TABLE IF EXISTS priority_rule_safety_report;
DROP TABLE IF EXISTS role_permissions_admin_only_stripped;
