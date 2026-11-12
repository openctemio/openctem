# Operations

An operation is long-running work a person started from the API. The request
creates it and answers with it; the caller reads it back until it ends.

Status: shipped for bulk changes of findings by filter
([findings-bulk-by-filter.md](findings-bulk-by-filter.md)). Background
exports over 10,000 rows, large imports and recalculations are planned on the
same resource (research 230 D10); until then a findings export is capped at
10,000 rows ([list-query-contract.md](list-query-contract.md#export)).

## API

`GET /api/v1/operations/{id}` (needs `findings:read`, the only kinds today
being findings work):

```json
{
  "id": "0190...", "kind": "findings_bulk_status", "status": "running",
  "total": 4200, "processed": 1300, "succeeded": 1290, "skipped": 6, "failed": 4,
  "items": [{"id": "<finding id>", "outcome": "failed", "reason": "..."}],
  "error": "", "created_at": "...", "updated_at": "...", "finished_at": null,
  "self": "/api/v1/operations/0190..."
}
```

- `status`: `running`, `succeeded`, `failed` (the run stopped on an error,
  `error` says why) or `interrupted`.
- `items`: the items that did not succeed, at most 200.
- Poll every 1–2 seconds while `running`. Responses are `Cache-Control: no-store`.

## Rules

- **Creator only.** Every read is bound to the tenant and the creator. Any
  other caller, tenant or unknown id gets `404`.
- **One running operation per person** (a partial unique index). A second one
  is `409 OPERATION_RUNNING`.
- **Interrupted.** The run moves `updated_at` after each chunk. A `running` row
  that has not moved for 5 minutes reads as `interrupted` (the API process
  stopped) and no longer blocks its creator. Items already processed stay
  done; sending the same request again finishes the rest.
- **Idempotency.** A request with `idempotency_key` that is retried returns the
  first request's operation. The same key with a different request is
  `422 IDEMPOTENCY_KEY_REUSED`.
- **Budget.** A kind may have a per-tenant budget (bulk changes by filter:
  20,000 findings per hour). The total is read and the row inserted under one
  per-tenant advisory lock, so people creating at the same moment, on any
  replica, cannot overrun it together.
- **Runner.** The run happens in the API process that took the request, with
  the request's identity (tenant, user, data scope, permissions) and a
  30-minute deadline. A panic in the run ends the operation as `failed` with a
  generic `error` (details go to the log only); it never stops the process. It is not queued across replicas; a durable runner is
  planned with the other kinds.
- **Erasure.** Rows are deleted with their tenant or their creator's account.

## Key files

- `api/migrations/NNNNNN_operations.up.sql` (table `operations`)
- `api/pkg/domain/operation/operation.go`
- `api/internal/infra/postgres/operation_repository.go`
- `api/internal/infra/http/handler/finding_bulk_filter_handler.go` (`GetOperation`)
