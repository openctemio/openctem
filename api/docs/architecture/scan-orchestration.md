# Scan Orchestration

How scans become work for sensors. The run model (Scan → Run → Task, states,
schedules, timeouts) is in [scan-lifecycle.md](scan-lifecycle.md) and
[RFC-046](../rfcs/RFC-046-scans-redesign.md); the stage catalogue, planner and
chaining in [scan-stages.md](scan-stages.md); routing to sensors by network in
[scan-zones.md](scan-zones.md); the target gate in
[active-probe-gate.md](active-probe-gate.md). This page keeps the details those
documents do not repeat.

## Components

| Component | Where | What it does |
|---|---|---|
| Scan service and trigger | `internal/app/scan/` (`trigger.go`, `targets.go`) | resolves targets (scope, exclusions, zones, type gate) and starts a run |
| Scan run service | `internal/app/scanrun/` (`run.go`, `step.go`) | creates the run and its step runs, queues each step as a command, advances the run on step completion or failure, settles it |
| Commands | `pkg/domain/command`, `internal/infra/postgres` | the queue sensors poll and claim (with leases) over `/api/v2/sensor/*` |
| Scheduler and reapers | `internal/infra/controller/` | scheduled occurrences, command expiry, lease expiry, run timeouts |

## Step commands name their scanner

A scan workflow step becomes a `scan` command whose payload names the step's
tool twice: `scanner` (what the sensor SDK runs, `ScanCommandPayload`) and
`preferred_tool` (read by the platform's tool gate, which offers the command only
to a sensor whose effective tools include it). Direct run targets are copied to
the top-level `targets`. `required_capabilities` is the step's capability list;
the queue-time step check requires it to be a subset of the tool's catalog
capabilities, and the poll offers the command only to a sensor that advertises
all of them.

The recon tools (subfinder, dnsx, naabu, httpx, katana) ship in the sensor's
full and platform images and take a target list, so a run of one of them is one
command with every target, like nuclei.

**System presets**: every step of an active preset names a shipped tool with
catalog capabilities. "Web Vulnerability Scan" and "API Security Testing" are
inactive: their tools (dalfox, sqlmap, kiterunner, ffuf) are not shipped and they
are intrusive, so they stay opt-in (RFC-036 O3).

## Editing a scan workflow keeps its run history

A scan workflow's steps are edited in place. Every write (the builder's full
save, `PUT /api/v1/scan-workflows/{id}` with `steps`, and the single-step add,
update and delete endpoints) goes through one repository call,
`StepRepository.MutateSteps`
(`internal/infra/postgres/scan_workflow_step_mutate.go`), in one transaction:

1. **Lock the scan workflow** (`FOR UPDATE`, tenant-scoped; another tenant's
   workflow is not found). A run insert takes a `KEY SHARE` lock on the same row
   through its foreign key, so a save and a run start never interleave.
2. **Refuse while a run of the workflow is pending or running**
   (`409`, error code `PIPELINE_RUN_ACTIVE`). A running run reads the step
   definitions as it advances, so a mid-run edit would change what the rest of
   that run does.
3. **Match the saved steps to the current ones**: by the step `id` the client
   sends, then by `step_key`. Only ids of the workflow's own steps are honored; a
   client-side temporary id or another workflow's step id makes the entry a new
   step with a server-generated id.
4. **Update matched steps in place** (they keep their id, so their step runs and
   chaining inputs in `scan_step_outputs` stay attached), insert new ones, delete
   the rest.

Deleting a step never deletes history: `scan_run_steps.step_id` is
`ON DELETE SET NULL` (migration 001159), and each step run carries the step's
`step_key`, `step_name` and `tool` as they were when it was created. The run
detail shows a removed step's runs by that snapshot.

## Prometheus metrics

No metric carries a tenant, sensor, scan workflow, run or user id as a label
(RFC-046 B9, enforced by `internal/metrics/labels_test.go`); per-tenant views
come from logs (`tenant_id`, `run_id`) and traces. The metrics are defined in
`internal/metrics/metrics.go`; operator alerting on them is in
[Monitoring and alerting](../operations/monitoring.md).

| Metric | Labels | What |
|---|---|---|
| `scan_runs_total` | `status` | runs started and settled |
| `scan_runs_in_progress` | — | runs in progress (this replica) |
| `scan_run_steps_total` | `step_key`, `status` | step outcomes |
| `commands_total`, `commands_expired_total` | `type`, `status` / — | command outcomes, expiries |
| `command_claims_total` | `mode` (`claim`, `claim_n`) | commands sensors claimed |
| `command_leases_expired_total` | — | commands re-queued after their lease ran out |
| `scan_runs_reaped_total` | `reason` (`deadline`, `unclaimed`) | runs the timeout controller ended |
| `scans_scheduled_total`, `scan_schedule_outcomes_total` | — / `outcome` | scheduler occurrences and what they became |

## Tenant isolation

Every scan, run, step run and command carries `tenant_id`; sensors poll and claim
only their own tenant's commands (platform sensors only platform work), and the
tenant comes from the sensor's authentication, never from the request body.
