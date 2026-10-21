### Fixed: the priority audit log no longer keeps rows with no information or rows of deleted organizations

- Entries whose class did not move are refused by the insert itself (every writer is covered), and the daily retention controller removes the residue of earlier versions (no-op rows) and the rows of organizations that no longer exist.
- Deleting an organization now erases its `priority_class_audit_log` rows in the same transaction (the table has no foreign key to organizations).
- Retention deletes in batches of 5,000 instead of one statement, so a large backlog no longer holds a long transaction.
