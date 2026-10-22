# Findings bulk by filter

"Select all N matching" on the findings list applies a change to every
finding the list's filter selects, on the server. Selected ids stay per page
(at most 100, `POST /findings/bulk/{status,assign}`).

Status: shipped (API). Verbs: status and assign. Add to task, retest and
export by filter are planned.

## API

```
POST /api/v1/findings/bulk/by-filter/status   findings:bulk_update + findings:status (+ step-up when closing)
POST /api/v1/findings/bulk/by-filter/assignee   findings:bulk_update + findings:assign
```

```json
{
  "filter": {"state": "open", "severity": "critical,high", "q": "log4j"},
  "expected_count": 214,
  "idempotency_key": "6f1c...",
  "status": "confirmed", "resolution": "note", "closure_reason": "fixed",
  "user_id": "<assignee, assign only>"
}
```

- `filter` is the list's GET params (a value is a string or a list of
  strings), parsed strictly against the findings registry. `view`, `page`,
  `per_page`, `cursor` and `sort` are refused: they are not part of a
  selection, so the client sends a saved view as its filter.
- Answer: `{"operation": {...}}` (see [operations.md](operations.md)). `200`
  when the change ran in the request (up to 1,000 findings, the operation
  already ended), `202` with `Location: /api/v1/operations/{id}` above that.

| Error | When |
|---|---|
| `400 INVALID_FILTER` | unknown or bad param, or a non-selection param |
| `409 SELECTION_CHANGED`, `details.count` | the filter, recompiled now in the caller's scope, selects another count than `expected_count`; the client re-confirms with the new count |
| `400 BULK_TOO_LARGE`, `details.max` | more than 10,000 findings |
| `400 BULK_NOT_ALLOWED` | target false positive, accepted or duplicate |
| `400 VALIDATION_FAILED` | a closing status without a note, or a bad body |
| `403 STEP_UP_REQUIRED` | a closing status without a recent sign-in |
| `403` | a missing permission (named), or no signed-in user |
| `409 OPERATION_RUNNING` | the caller has an operation running |
| `422 IDEMPOTENCY_KEY_REUSED` | the key was used with another request |
| `429` | the organization's hourly budget (20,000 findings by filter) is spent |

## How it works

1. The filter is compiled with `filterspec.Compile` as the caller: tenant
   first, data scope, pentest member rule, branch-only default. The same
   compile as the list, so the count is the list's total.
2. Up to 10,001 ids are selected, in id order. Over 10,000 is refused; a count
   other than `expected_count` is `409`.
3. The tenant's budget is the sum of by-filter operations in the last hour,
   read from the database, so every replica shares it.
4. An operation row records the run. A summary audit row (`finding.bulk_updated`
   with `by_filter`, the operation id, the verb, the target, the count, the
   filter's field:operator shape and a hash of the request, never filter
   values) is written when it starts and when it ends.
5. Findings are applied 100 at a time. Each chunk recompiles the filter as the
   caller restricted to the chunk's ids, so a finding that left the filter or
   the caller's scope since the count is skipped ("no longer matches the
   filter"). The chunk then goes through the same service as a bulk change by
   ids: per-finding transition and lifecycle rules, the data scope check,
   pentest findings left to the pentest module, and one audit row per changed
   finding.

## Threat model

| Threat | Control | Test |
|---|---|---|
| Out-of-scope or cross-tenant findings changed | Filter compiled as the caller; re-applied per chunk; ids checked again by the bulk service | memberA's filter on an out-of-scope asset selects 0; the whole-list change touches only FA |
| A typo or a stale page widens a destructive change | Strict filter; `expected_count`, 409 | unknown param 400; count mismatch 409 |
| Mass closure by mistake or with a stolen session | Step-up and a note on closing statuses; cap 10,000; tenant budget in the database; one running operation per person | step-up route list; budget 429; running 409 |
| Four-eyes bypass | False positive, acceptance and duplicate are never by filter | 400 BULK_NOT_ALLOWED |
| Double submit | Idempotency key replays the operation | replay returns the same operation |
| Reading another person's progress | Operation reads bound to tenant and creator | other member 404 |

Tests: `api/internal/infra/http/routes/findings_bulk_by_filter_db_test.go`.

## Key files

- `api/internal/app/finding/bulk_by_filter.go`
- `api/internal/infra/http/handler/finding_bulk_filter_handler.go`
- `api/internal/infra/postgres/finding_spec_repository.go` (`IDsWhere`)
