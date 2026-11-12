### Security: the database chains every audit row and refuses to change it

- Every tenant audit row is now chained by the database in the transaction that inserts it, over the whole row (actor, changes, metadata, message, severity, request and session ids, not only action, resource and result). Rows written straight into `audit_logs` by repository transactions and data migrations were left unchained before; they are covered now.
- `UPDATE` and `TRUNCATE` of the audit log and of the chain evidence tables are refused by the database. Only a platform rebaseline rewrites chain hashes, and nothing else on a chain row.
- Deleting an account or an organization no longer rewrites its audit rows (actor and organization were set to empty): the ids stay as recorded. Rows of organizations deleted earlier get their organization back from their chain row.
- Older chain rows keep their hash version and verify as before; the hourly verifier, the classification, the rebaseline, `chainaudit` and the retention archive understand both versions.
