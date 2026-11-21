# Findings bulk by filter

"Select all N matching" on the findings list applies a change to every
finding the list's filter selects, on the server. Selected ids stay per page
(at most 100, `POST /findings/bulk/{status,assign}`).

Status: shipped (API). Verbs: status and assign. Add to task, retest and
export by filter are planned. Dismiss (false positive or accepted risk, by ids
or by filter, at most 500) has its own flow: [Bulk dismiss](#bulk-dismiss).

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
   read from the database, so every replica shares it. It is checked by the
   insert of the operation under a per-tenant advisory lock, so concurrent
   requests by different people cannot overrun it together.
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
| Mass closure by mistake or with a stolen session | Step-up and a note on closing statuses; cap 10,000; tenant budget checked under a per-tenant lock; one running operation per person | step-up route list; budget 429; concurrent and in-flight creates refused over the budget; running 409 |
| Four-eyes bypass | False positive, acceptance and duplicate are never by filter; the status is parsed like the bulk service and the step-up gate (case, whitespace) | 400 BULK_NOT_ALLOWED for every spelling |
| A finding leaves the filter or the scope after the count | Each chunk re-applies the filter as the caller to its ids | the finding that left is skipped and not written |
| A crash in a background run takes the API down | The run recovers a panic and ends the operation as failed | panic in the request and in the background ends failed |
| Double submit | Idempotency key replays the operation | replay returns the same operation |
| Replaying someone else's key | Keys are bound to tenant and creator | another person's or another organization's key is a new operation |
| Reading another person's progress | Operation reads bound to tenant and creator | other member 404; another organization's operation 404 for its own creator |

Tests: `server/internal/infra/http/routes/findings_bulk_by_filter_db_test.go`,
`server/internal/app/finding/bulk_by_filter_test.go`,
`server/internal/infra/postgres/operation_repository_test.go`.

## Bulk dismiss

"Dismiss" marks up to 500 selected findings a false positive (default) or
accepts their risk, in one action. Status: shipped (API); the web dialog is
built on the redesigned console.

### Simplest path

Select rows (or "all N matching"), choose Dismiss, pick a reason, add a note
when the preview asks for one, confirm. The preview says how many are decided
now, how many go to approval as one request, and which are skipped and why.

### API

All three need `findings:bulk_update` and `findings:write`
(`internal/infra/http/routes/exposure.go`).

```
POST /api/v1/findings/bulk-dismissals/preview
POST /api/v1/findings/bulk-dismissals
{
  "finding_ids": ["<id>", ...],            // or "filter": {...} + "expected_count": N
  "status": "false_positive",              // or "accepted" (+ "expires_at", RFC 3339)
  "closure_reason": "detection_error",     // required
  "note": "What was checked",              // see note_required
  "idempotency_key": "<uuid>"              // required to apply
}
-> 200 {
  "bulk_id": "<id>",                        // apply only
  "status": "false_positive",
  "decided": ["<id>", ...],                 // decided alone now (apply)
  "grouped": {"batch_id": "<id>", "count": 3, "tier": "peer"} | null,
  "skipped": [{"id": "<id>", "reason": "not_found|cannot_move|pending_request|note_required|failed"}],
  "counts": {"decided": 38, "grouped": 3, "skipped": 2, "budget_overflow": 0},
  "step_up_required": true, "note_required": true, "note_min_length": 1, "replay": false,
  // preview only, at most 50 each, counts stay complete:
  "decided_now": [{"id", "title", "severity"}], "to_approval": [...], "skipped_items": [...],
  "same_rule": {"tool": "semgrep", "rule_id": "...", "count": 300, "suggest": true}
}

POST /api/v1/findings/bulk-dismissals/{id}/reopen
-> 200 {"bulk_id": "<id>", "reopened": ["<id>"], "skipped": [{"id", "reason": "changed|not_found|not_allowed"}], "group_canceled": true}
```

Errors: 400 `BULK_DISMISS_TOO_LARGE` (`details.count`, `details.max` 500;
more than 500 ids, or a filter selecting more: the count is exact), 409
`SELECTION_CHANGED` (`details.count`), 422 `IDEMPOTENCY_KEY_REUSED` (the key
was used with another request), 403 `STEP_UP_REQUIRED` (more than 25 decided
alone in the call and the last hour together, nothing changed), 400 for a missing reason or a note shorter than the
plan needs, 404 for an undo of another person's bulk, 409 for a second undo, one after 24 hours, or one while the apply is
still running.

### How it works

`internal/app/finding/bulk_dismiss.go`. The plan (shared by preview and
apply):

1. The selection: the ids (deduplicated), or the filter compiled in the
   caller's scope (`IDsWhere`, capped at 501, then `CountWhere` for the exact
   count when it is over) checked against `expected_count`.
2. The findings in one query (`GetByIDs`), the caller's scope in one or two
   (`FindingFilterForCaller`, asset only, as a single request's check).
   Out-of-scope and other-tenant ids are `not_found`, exactly like missing
   ones, and the preview never names them.
3. Per finding, the evaluation of a single request (`RequestApproval`): the
   organization's lifecycle (not a request move, or already in that status:
   `cannot_move`), a pending request (`pending_request`), then
   `evaluateFindingRequest`. Decided alone when the policy gives the `single`
   tier and the request is not an automation's (`CanApprove` only from the
   person's own session with `findings:approve`; an API key or MCP token never
   decides alone; AI agents and asset owners never do). An organization's
   only member never accepts a risk alone in bulk (their own approval with an
   authenticator code applies, as for one finding).
4. The budget: at most 1,000 decided alone per person per rolling 24 hours
   (the sum of `decided_count`); the rest goes to the group
   (`budget_overflow`), never dropped.
5. The group as it will be asked (`planGroupException`): its tier and the
   members it takes; the note it needs is known before anything changes.

Apply: replay by key first (the stored result, `replay: true`); then the
note and the re-authentication (more than 25 decided alone, counting the
calls of the last hour) are checked
before anything changes; the bulk row is inserted under a per-(tenant,
person) advisory lock that reserves the budget; each decided-alone finding
goes through `applySinglePerson` (its own transaction, timeline entry with
`bulk_id`, the level and facts re-read with the finding locked); a finding
that raced with a raised level joins the group, or is reported
`note_required` when the bulk has no note; one `RequestGroupException`
(source type `selection`, source id = the bulk id, label such as "42
findings, filter: severity=high"); the status side effects once
(`afterApplied`); the outcome stored on the row. Once started the apply does
not stop with the request (5-minute bound); a client that gave up retries
with its key.

Undo: the creator only, within 24 hours, once (the row moves `applied` to
`undone` in one conditional update, once the apply has recorded its outcome;
before that the undo answers 409 and can be retried). Each finding the bulk decided alone that
is still in the status it set goes back to `confirmed` through the normal
status path (`UpdateFindingStatus`, note "Undo of bulk dismissal <id>"); one
that moved since is left as it is (`changed`). The bulk's pending group is
canceled. Nothing is deleted.

Notes: the note follows the rule of a single request
([finding-status-lifecycle.md](finding-status-lifecycle.md), "When a note is
required"): optional when every finding is decided alone and none is serious;
otherwise the longest minimum of the plan. The preview's `same_rule` names the
tool rule most selected findings share; with 20 or more the web suggests a
suppression rule instead (a rule also covers new findings and expires).

Performance: the organization-wide lookups of the policy (settings, AI-agent
check, security pool, approver directory, each approver's data scope, the
policy facts of every finding) are read once per call (`approval_memo.go`;
`PolicyFactsMany`; `datascope.Enforcer.PrimeAssets`); the preview of 500 runs
about 20 statements. An apply costs the per-decision write of a single request
per finding decided alone (about 8 statements) and a few per group member.
Known limit: an apply of 500 decided alone takes about 17 seconds, because the
findings are written one at a time; a batched write path is a planned
follow-up.
Second look: a bulk deciding 10 or more findings alone, with the organization's
second-look share above 0, always raises at least one second look (per-finding
sampling as for a single request; when it raised none, one decided finding is
chosen with crypto/rand).

### Threat model

Bulk dismiss is the cheapest way to hide findings (an insider, a stolen
session, an API key, an AI agent). Controls: the same per-finding policy as a
single request with the in-transaction re-check (no bulk shortcut); tenant from
the principal and scope filtering with not-found answers; 500 per call;
1,000 decided alone per person per day; step-up above 25 (calls of the last hour add up); per-finding
activity and audit rows plus one `finding.bulk_dismissed` audit event (high
severity above 100 decided alone, with an immediate notice to the owners:
in-app and the organization's security alert channel); undo through the
normal status path. Table `finding_bulk_dismissals` (migration
20261119095221) is tenant-scoped and read by its creator only; it keeps no
note (the note is on each finding's timeline).

Tests: `server/internal/infra/http/routes/finding_bulk_dismiss_db_test.go`
(partition by level, never alone for asset owner / delegated credential / AI
agent, skips and isolation, size and selection, idempotency, step-up and
budget, raised-level race, undo, note rule; `BULK_DISMISS_PERF=1` for the
10,000-finding measurement), `server/internal/infra/http/handler/finding_bulk_dismiss_handler_test.go`.

## Key files

- `server/internal/app/finding/bulk_by_filter.go`
- `server/internal/infra/http/handler/finding_bulk_filter_handler.go`
- `server/internal/infra/postgres/finding_spec_repository.go` (`IDsWhere`)
- `server/internal/app/finding/bulk_dismiss.go`, `approval_memo.go`, `approval_note.go`
- `server/internal/infra/http/handler/finding_bulk_dismiss_handler.go`
- `server/internal/infra/postgres/finding_bulk_dismiss_repository.go`, `finding_approval_policy_many.go`
