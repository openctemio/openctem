# Automations: how runs start and how many

Automations are the event rules at `/api/v1/workflows` ("When → If → Then"); design: [RFC-125](../rfcs/RFC-125-automation-simulate-and-go-live.md).
This page covers how an event becomes runs and the limits on them. A
redesign (a durable event journal, versions, retries) is **Planned**. Who a run acts as is covered in
[authorization-matrix.md](authorization-matrix.md), "Automation runs act as
one person".

## The catalog: what the engine runs

`GET /api/v1/workflows/catalog` (`findings:workflows:read`) lists every
trigger, action and notification type the engine runs, in builder order,
with the permission each needs and whether the caller holds it. The console
builds its palette from this answer, and the API refuses a node of any other
type. The lists live in `pkg/domain/automation/catalog.go`; `IsValid` on
each type is built from them.

| Kind | Types |
|---|---|
| Trigger | `manual`, `finding_created`, `finding_status_changed`, `asset_discovered`, `scan_completed`, `ai_triage_completed`, `ai_triage_failed` |
| Action | `assign_user`, `update_status`, `add_tags`, `remove_tags`, `create_ticket`, `update_ticket`, `trigger_scan`, `trigger_ai_triage` |
| Notification | `slack`, `teams`, `email`, `webhook` (a registered integration) |

**Removed types.** The `schedule`, `finding_age`, `finding_updated` and
`webhook` triggers, the `assign_team`, `update_priority`, `run_script`,
`http_request` and `trigger_pipeline` actions and the `pagerduty`
notification never ran (nothing fired them, or every run failed or was
refused) and are no longer types. Migration `automations_removed_types`
switched off every automation that still held one and set
`automations.disabled_reason = uses_removed_type`; nothing was deleted, and
the stored headers of `http_request` nodes were dropped (they were often
credentials in plain config). Such an automation stays readable
(`disabled_reason` and `unsupported_features` on `GET /workflows/{id}`), and
cannot be switched on until the node is replaced; saving a graph of known
types clears the reason. Scans keep their own schedules; a sweep schedule for
rules (a saved filter evaluated on a schedule, for digests and periodic
sweeps) is designed separately and is not a trigger yet.

## Versions and mode

The nodes and edges of an automation are its **draft**. `POST
/api/v1/workflows/{id}/publish` stores the draft as an immutable row of
`automation_versions` (definition, SHA-256 digest, risk class, publisher)
and makes it the **published version**: the automation switches to
`mode = live` and `published_version_id` points at it. The previous
published version becomes `superseded`.

| Mode | Runs execute | Effects |
|---|---|---|
| `simulate` (every new automation) | the draft | none: action and notification steps record what they would do |
| `live` | the published version, pinned when the run is created | the steps act |

- A run pins its version (`automation_runs.version_id`, `mode`). Editing the
  draft never changes a live automation, nor a run already created; an
  unpublished trigger change never changes what starts it (the dispatcher
  matches a live automation on its published trigger).
- `draft_changed` on `GET /workflows/{id}` says the draft differs from the
  published version (digest of the steps, ignoring node positions).
- `POST /workflows/{id}/versions/{versionId}/rollback` publishes an older
  definition again as a new version; history keeps every version
  (`GET /workflows/{id}/versions`, `GET /workflows/{id}/versions/{versionId}`).
- `PUT /workflows/{id}/mode {"mode":"simulate"}` switches back in one call
  and keeps the published version. Live is reached only by publishing.
- **Owner.** Publishing (and switching on) makes the caller the owner live
  runs act as. Editing the draft does not change the owner any more: a draft
  only simulates, and nothing an editor changes acts before someone publishes
  it. Publishing needs the permission of every step, like switching on.
- The draft cannot be replaced while a simulate run of it waits or runs;
  live runs do not block an edit. Run steps keep the node id of the
  definition they ran (the foreign key to the draft's nodes is gone, so
  replacing the draft no longer deletes earlier runs' step history).
- **Upgrade.** Migration `automation_versions` makes every automation that
  is switched on version 1, published by its owner, live, so working rules
  keep acting. Automations that are off stay in simulate without a version.

### Simulate by construction, the run trace and deliveries

An action or notification step is either **executed** (the handlers, which
hold the services that change data, open tickets, start scans and send
messages) or **evaluated** (`internal/app/automation/evaluate.go`). A simulate
run reaches only the evaluator, whose single dependency is a read-only finding
reader: by type it cannot write or reach the network. A unit test walks the
evaluator's fields and fails if anything else appears there, and another runs
an automation whose live handlers call a fake server: in simulate the server
receives nothing. The step's permission and the subject's scope are still
checked for the owner before evaluation, so a simulation also shows steps the
owner may not run.

Each step records a trace on `automation_run_steps`: `in_count` (subjects
that reached it), `out_count` (acted on, or would act on) and `skipped`, per
reason (`condition_false`, `branch_not_taken`, `no_change`, `no_subject`,
`refused:not_authorized`). Every notification and ticket step records a
delivery in `automation_deliveries`: channel, target, mode, status
(`simulated`, never sent; `sent`, `failed`, `held` by a create policy),
attempts, external reference, and a payload limited to an allow-list
(title, severity, subject, provider, project, issue type, repository, body
length): never a body, headers or a secret.

- `GET /workflow-runs/{id}` returns the steps with their trace, the
  deliveries and `retained_until`.
- `GET /workflows/{id}/trace?mode=simulate&days=30` sums the trace and the
  deliveries per channel over the window.
- **Scope.** Runs record the finding or asset their trigger names
  (`subject_id`). A run about a subject outside the caller's data scope, or
  about a pentest finding of a campaign the caller is not a member of
  (administrators excepted), is not listed and answers 404, and the trace counts only runs the caller may
  see (runs without a subject, such as a finished scan, are visible to every
  reader).
- **Retention.** Simulate runs are kept 30 days, live runs and their
  deliveries 180 days; the `automation-run-retention` controller (every 6
  hours, one replica) deletes older finished runs in batches.

### Preview and validate

Both take the draft in the body (`nodes`, `edges`) or, without one, the saved
draft; both read only and need `findings:workflows:write`.

- `POST /workflows/{id}/preview {"limit": 1..100}` runs the draft against the
  latest subjects of its trigger's kind (findings, or assets for
  `asset_discovered`; a scan trigger has none) **that the caller may read**,
  applies the trigger's filters, walks the graph in memory through the
  simulate evaluator and returns per-step counts, the sample ids and what it
  would send. Nothing is stored or sent. One call per 10 seconds per user
  (429 `RATE_LIMITED`); a limit above 100 is a 400. A call without a person
  (an API key) is refused: samples follow a person's scope.
- `POST /workflows/{id}/validate` returns `problems` (block publishing) and
  `warnings`: `UNSUPPORTED_TYPE`, graph codes (`GRAPH_CYCLE`,
  `GRAPH_UNREACHABLE`, `GRAPH_EDGE`), `TRIGGER_CONFIG_INVALID`,
  `CONDITION_INVALID`, `CONDITION_UNKNOWN_FIELD` (warning), `CONFIG_MISSING`,
  `INTEGRATION_MISSING` (not set, or not an integration of this organization),
  `OWNER_LACKS_PERMISSION` (the caller would own the automation once they
  publish it) and `NO_SIMULATION_SINCE_EDIT` (warning). Ten calls per 10
  seconds per user.

Risk classes (`pkg/domain/automation/risk.go`): low (tags), elevated
(status, assignment, tickets, notifications, AI triage), high (scans, and
any automation that lets automation-caused events start it). The go-live
gate built on them is described in RFC-125 §2 D6.

## One run per subject

An event starts **one run per matching subject**. A batch of new findings
(`finding_created`, from ingest) starts one run per finding that passes the
trigger filters. With 40 new critical findings, a "critical → ticket"
automation files 40 tickets. Before this, it started one run, for the first
finding of the batch, and the other 39 were silently dropped.

Every run records its subject (`automation_runs.subject_id`: the finding or
asset). Where the event has a stable identity, the run also gets an
idempotency key (`automation_runs.idempotency_key`, unique per automation), so
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
memory, so a restart loses runs that are waiting or running. The
`automation-run-reaper` controller fails those runs and their open steps. It
runs on start and every 15 minutes, on one replica, and acts on runs more than
an hour old. Each step gets at most 30 seconds. A step that runs out fails
with `step timed out`, and the run goes on to its next step.

## Loop guard

An automation step can cause the event that starts an automation. For
example, a status change is a `finding_status_changed` event, and a scan an
automation starts ends in a `scan_completed` event. Such an event carries its
cause: the run, the automation and the chain depth. A run started by a person
or by the platform has depth 0. An event caused by a run at depth *n* has
depth *n + 1*. The cause travels in the step's context for synchronous
producers, and in the scan run's context for a scan. An automation-caused
event:

- never starts the automation that caused it;
- starts another automation only when that automation allows it
  (`trigger_config.allow_automation_triggers: true`). This is off by default;
- starts nothing beyond depth 3;
- starts an automation at most once per subject in 10 minutes (the subject
  cooldown). AI-triage events have the same cooldown, because a triage
  request made by an automation comes back as a triage event the guard cannot
  trace.

Two automations that undo each other therefore stop after at most four
levels instead of looping. A refused start is logged with its reason
(`automation not started: loop guard`).

## Failing automations pause

When the latest 20 finished runs of an automation all failed, the platform
switches it off (`is_active = false`, audited as a deactivation with reason
`consecutive_failures`). Records of throttled events are not counted. Someone
must fix the automation and switch it on again. Run statistics are written on
the automation as it is stored when the run ends, so a switch-off made while a
run executed is not undone.

Code: `pkg/domain/automation/run_limits.go` (the values),
`internal/app/automation/loop_guard.go` (the loop guard),
`internal/infra/controller/automation_run_reaper.go` (the reaper),
`WorkflowRunRepository.CreateRunIfUnderLimit` (enforcement),
`WorkflowEventDispatcher.dispatchFindingsCreated`, and
`WorkflowExecutor.ExecuteAsyncWithTenant`.
