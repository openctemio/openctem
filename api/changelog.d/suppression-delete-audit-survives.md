### Security: the audit row of a deleted suppression rule is no longer erased with the rule
- `suppression_rule_audit.suppression_rule_id` was `ON DELETE CASCADE`, so the "deleted" row that records who deleted a rule was removed by the delete itself. The column is now nullable with `ON DELETE SET NULL` (migration 003379), and the row is written inside the delete's transaction (no row, no delete) with the rule id kept in its details.
- A rule deletion is also recorded in the tenant audit log as `suppression_rule.deleted`.
