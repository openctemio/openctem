# Automations: how runs start and how many

Automations are the event rules at `/api/v1/workflows` ("When → If → Then").
This page covers how an event becomes runs and the limits on them. The
redesign (a durable event journal, versions, retries) is planned in research
doc 61. Who a run acts as is covered in
[authorization-matrix.md](authorization-matrix.md), "Automation runs act as
one person".

## One run per subject

An event starts **one run per matching subject**. A batch of new findings
(`finding_created`, from ingest) starts one run per finding that passes the
trigger filters. With 40 new critical findings, a "critical → ticket"
automation files 40 tickets. Before this, it started one run, for the first
finding of the batch, and the other 39 were silently dropped.

Every run records its subject (`workflow_runs.subject_id`: the finding or
asset). Where the event has a stable identity, the run also gets an
idempotency key (`workflow_runs.idempotency_key`, unique per automation), so
the same event never starts an automation twice:

| Trigger | Subject | Idempotency key |
|---|---|---|
| `finding_created` | the finding | `finding_created:<finding id>` |
| `finding_status_changed` | the finding | none (every change is an event) |
| `ai_triage_completed` / `_failed` | the finding | `<trigger>:<triage id>` |
| `scan_completed` | none | none (a scan run settles once) |
| `asset_discovered` | none (one run per ingest batch) | none |
| manual | the finding or asset named in the request | none |

## Limits

Runs are bounded **where they are created**, inside one transaction that
holds the automation's row lock. Events are not dropped silently:

| Limit | Value | Over it |
|---|---|---|
| Runs of one automation in the last hour | 200 | refused as throttled |
| Runs of one organization in the last hour | 5,000 | refused as throttled |
| Waiting or running runs of one automation | 100 | refused (`MAX_CONCURRENT_RUNS`) |
| Waiting or running runs of one organization | 500 | refused (`MAX_CONCURRENT_RUNS`) |

The first throttled refusal in an hour records one failed run whose message
starts with `THROTTLED:`, so the automation's run history shows that events
were dropped. The dispatcher stops asking for the rest of that batch.

**Execution.** At most 10 runs execute at once per organization and 50 in
total. Other runs wait for a free slot instead of failing. A run that has
waited 30 minutes fails with `not started: waited …`. Execution happens in
memory, so a restart loses runs that are waiting or running.

Code: `pkg/domain/workflow/run_limits.go` (the values),
`WorkflowRunRepository.CreateRunIfUnderLimit` (enforcement),
`WorkflowEventDispatcher.dispatchFindingsCreated`, and
`WorkflowExecutor.ExecuteAsyncWithTenant`.
