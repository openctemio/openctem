### Security: the platform administrators' audit log is append-only and hash-chained

- `admin_audit_logs` refuses updates, deletes and truncation (database triggers; the API role also loses its `UPDATE`/`DELETE`/`TRUNCATE` grants), and every row is linked into a SHA-256 chain computed by the database, so an edited or removed row is detectable. Migration 002401 chains the existing rows in the order they were written.
- Retention (`ADMIN_AUDIT_RETENTION_*`) now goes through `admin_audit_prune`: it removes only the oldest rows, never any newer than one year (a lower `ADMIN_AUDIT_RETENTION_DAYS` acts as 365), and anchors the chain where it stopped.
- New: `GET /api/v1/admin/audit-logs/chain` (any administrator) and the Security > Activity banner show whether every entry verifies; `bootstrap-admin verify-audit [-json]` (admin-cli image) does the same from the command line and exits 1 on a break.
- Deleting an administrator no longer clears `admin_id` on their audit rows (the foreign key is dropped).
- **Upgrade note:** nothing to run: the migration revokes the grants itself, and the `db-roles` bootstrap keeps them revoked. Tooling that deleted rows from `admin_audit_logs` directly must use `SELECT admin_audit_prune(cutoff, max_rows)` instead.
