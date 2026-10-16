### Added: one exception decision for a remediation task's open findings

- `POST /api/v1/remediation/tasks/{task_id}/exception/preview` and `POST .../exception` request one accepted risk or false positive over the task's open findings (at most 500), decided once under the approval policy: the highest member tier, the union of exclusions (owners of any member's asset), and each member's own acceptance cap. RFC-111 §7.
- `GET /api/v1/approvals/batches`, `GET /api/v1/approvals/batches/{id}`, `POST /api/v1/approvals/batches/{id}/approve|reject|cancel`. The last required approval applies every member in one transaction; a member whose finding moved is canceled. Member requests cannot be decided alone (409 `BATCH_MEMBER`); approval responses carry `batch_id`.
- Migrations `002788_approval_batches` (new table, nullable `batch_id` with a `NOT VALID` foreign key) and `002789` (validate).
