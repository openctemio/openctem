# Placement: which sensor can take a task, and why a task waits

Status: **shipped** (explainer and the run task endpoint). Design:
[RFC-030](../rfcs/RFC-030-scan-work-distribution.md) §5.13.

A scan task (a command) waits in the queue until a sensor of its
organization claims it. The claim decides who may take it. The placement
explainer reads the same checks back for one task and every sensor of the
organization, so the run page can say *why* a task waits and what would fix
it, instead of "Waiting for a sensor".

## What the claim checks, in order

| Layer | Check | Reason code when it fails |
|---|---|---|
| Job | not expired | `expired` |
| Job | due (not deferred to its scan window's next opening) | `window_closed` |
| Job | no other running task of the organization holds one of its hosts (one its settled targets have not released) | `host_busy` |
| Job | the sensor that last took it did not hand it back for its own per-host limit (only while the hosts look free to the platform) | `sensor_hosts_busy` |
| Sensor | sensor active (not disabled or revoked) | `inactive` |
| Sensor | sensor checking in (online or late) | `offline` |
| Claim SQL | not reserved for another sensor | `pinned_elsewhere` |
| Claim SQL | in the task's scan zone, with the tool | `outside_zone` |
| Claim SQL | the sensor reported the tool installed | `tool_missing` |
| Claim SQL | the sensor has not refused this task | `refused_earlier` |
| Claim SQL | every required capability offered | `capability_missing` |
| Claim SQL | every required feature *reported by the sensor* (`required_features`: `net.confined@1` for a web-scoped nuclei job) | `not_confined` |
| Dispatch gate | the sensor grant admits the task | `grant_<dimension>` (`grant_tools`, `grant_tier_ceiling`, `grant_target_network`, …) |
| Dispatch gate | the job's tier on this sensor is within the scan's intensity | `intensity` |
| Dispatch gate | the grant and policy could be read (fail closed) | `policy_unavailable` |
| Dispatch gate | private targets: the sensor enforces a local policy when the organization requires one | `private_needs_local_policy` |
| Dispatch gate | the organization enabled the opt-in the task uses | `opt_in_disabled` |
| Dispatch gate | the sensor's own local policy accepts the task | `local_policy_refuses` |
| Slots | a free scan slot (eligible but busy otherwise) | `no_free_slot` (counted as *busy*) |

The claim SQL lives in `internal/infra/postgres/command_repository.go`
(`pendingForSensorWhere`); the dispatch gate in
`internal/app/command/local_policy.go`.

## The shared fleet

When no sensor of the organization may take a task, the answer says
whether the shared fleet was an option (`shared_fleet`): `not_used` (the
organization may use shared sensors, but the task was routed to its own,
for example a scan set to run on the organization's sensors only) or
`not_allowed` (it may not now; `shared_fleet_reason` is the access policy's
reason, English). The run page shows it under the summary, so a run does
not wait in silence until its timeout (research/191 W-1).

## Waiting for hosts

When `host_busy` holds a task, the answer says how many of its hosts other
tasks of the organization hold and which tasks (`host_wait`: `hosts_held`
of `hosts_total`, at most three holders, the one holding the most first,
each with its tool, and its task, run and step when the caller can read
that run). It never names a host. The holders are read with the holder half
of `hostFreePredicate` (`HostHolders`): tenant-scoped, and a key a holder
released because its targets settled no longer counts. The run page shows
"Waiting: 10 of its 10 hosts are being scanned by httpx (step http). It
starts when those hosts are free." instead of "should start shortly", with a
link to the run that holds them. `host_wait` also gives `targets` and
`can_start`, how many of the task's targets are on hosts nobody holds (-1
when its keys cannot all be attributed to its targets); a claim with a free
slot splits those off when at most half of the targets wait
([scan orchestration](scan-orchestration.md)). The task list flags such a
task (`waiting_on_hosts`) and, for at most 25 waiting tasks of a page, gives
the same `host_wait` (`RunTaskHostWait`: the task must be the run's and
pending). The row reads in full, for example "Waiting for 2 of its hosts,
held by nuclei (step templates, run 1a2b3c4d); 21 of its 23 targets are on
free hosts". A sensor that hands a task back for its own per-host
limit ("its hosts are busy on this sensor") is stored as the release code
`hosts_busy`; while the platform sees the hosts free, the explainer names it
`sensor_hosts_busy`.

## How the explainer stays true

- **Same code, not a copy.** The repository evaluates the job and sensor
  predicates with the very SQL fragments the poll and the claim use
  (`zoneClaimPredicate`, `toolClaimPredicate`, `refusedByPredicate`,
  `capabilityClaimPredicate`, `scheduledDuePredicate`, `hostFreePredicate`),
  bound to each sensor row instead of a parameter
  (`command_placement.go`). The dispatch gate is called as is.
- **Agreement test.** `TestPlacement_AgreesWithTheClaim`
  (`internal/infra/postgres/command_placement_db_test.go`) runs a table of
  tasks (zoned, unzoned, capability-scoped, tool-less, pinned, refused,
  deferred) against sensors that differ in zone, tools, capabilities and
  grant, and checks for every pair that the explainer calls the sensor
  eligible exactly when the sensor's poll returns the task.
- **Read-only and never authoritative.** The explainer changes nothing and
  decides nothing; the claim stays the only authority.
- Gate checks run only for sensors that pass the claim SQL, as the poll
  does; a sensor blocked by the SQL lists those reasons only.

## Jobs that need a confined sensor

A web-scoped nuclei job (the tenant excluded a path on the host) keeps to
its scope only through the task forwarder of a network-confined sandbox.
The step (or a web-scoped nuclei validation or retest) stamps
`required_features: ["net.confined@1"]` on its commands, and
the claim's feature gate (`featureClaimPredicate`, on the poll, the batch
claim, the claim by id and the doorbell count) offers them only to a sensor
whose own report lists `net.confined@1`; a capability an administrator
declared never counts, because confinement is something only the sensor's
runtime can enforce. Other sensors leave the job queued (`not_confined`).
When the organization has no active sensor that reported it, the step is
refused when it is queued, with `NO_CONFINED_SENSOR` (class `placement`,
never retried), instead of waiting until the run's deadline. The sensor
advertises `net.confined@1` from its runtime status only (sensor and sdk-go),
and still refuses a web-scoped job it cannot confine (`WEB_SCOPE_UNSUPPORTED`)
as defence in depth.

## API

`GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement` (`scans:read`):

```json
{
  "queued": true, "platform": false,
  "job_reasons": [],
  "evaluated": 3, "truncated": false,
  "eligible": 1, "busy": 1,
  "blocking": [{"code": "tool_missing", "count": 2}],
  "sensors": [{"id": "…", "name": "dmz-1", "eligible": true, "busy": true, "reasons": []}]
}
```

- `queued: false`: the task no longer waits; nothing else is filled.
- `platform: true`: the task waits for platform scanning; no sensor is
  evaluated or named.
- `sensors` is present only for a caller who also has `sensors:read`; any
  reader of the run gets the counts and codes.
- At most 100 sensors are evaluated (by name); `truncated` says there were
  more.

## Run page

- **Tasks table:** a queued task that is not waiting for its scan window has
  a "Why waiting?" toggle. It asks the endpoint above only when opened and
  shows the summary (how many sensors can take the task, how many are busy),
  each reason with its count, what it means, the fix and a link to the page
  that applies it, and, for a caller with `sensors:read`, each sensor's
  verdict (`web/src/features/scans/components/task-placement.tsx`).
- **Step panel:** a failed, partial, skipped or canceled step shows its error
  code, its class and the code's meaning, fix and link
  (`code-help.tsx`).
- Every step error code (`pkg/domain/scanrun/failure.go`) and placement
  reason (`pkg/domain/command/placement.go`) has an entry with en and vi
  text (`web/src/features/scans/lib/placement-help.ts`); a web test reads
  both Go files and fails on a code without one.

## Security

- **Tenant isolation.** The tenant comes from the caller's session. The run
  passes the run access check first; the task must be a command of that run
  and of that tenant, else 404 (`ExplainRunTaskPlacement`). Every query
  carries the tenant, and the sensor join is on the command's tenant, so
  another organization's sensors are never read.
- **Platform scanning** is never broken down: platform sensors are
  excluded from the sensor list, and a platform task names none.
- **Least privilege inside the tenant.** Sensor names and per-sensor
  verdicts need `sensors:read` on top of `scans:read`.
- **No widening.** Reason codes describe the claim; nothing a sensor
  reports can make the explainer (or the claim) give it more work.

## Key files

- `pkg/domain/command/placement.go`: reason codes and the repository port.
- `internal/infra/postgres/command_placement.go`: the predicates read back.
- `internal/app/command/placement.go`: the explainer.
- `internal/infra/http/handler/scan_run_task_placement_handler.go`: the endpoint.
