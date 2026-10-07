### Behaviour change: scope responses name people and say where an entry came from

- Every actor field of a scope entry or exclusion (`created_by`,
  `approvals[].approver`, `rejected_by`, an exclusion's `approved_by`) is now
  an object: `{"kind": "user", "id", "name"}`, `{"kind": "user", "id",
  "former_member": true}` or `{"kind": "system", "code"}` (for example
  `upgrade_wildcard_split` instead of `system:migration-000292`). Names come
  only from the organization's current members; no e-mail is returned.
  **Upgrade note:** API clients that read `created_by` as a string read
  `created_by.id` now.
- New `origin` on entries and exclusions (migration `001244`): `manual`,
  `request`, `import`, `review_rule`, `refusal_fix`, `seed`,
  `seed_migration` or `system`, set by the path that created the row.
  Existing rows are `manual`, rows the platform wrote are `system`.
