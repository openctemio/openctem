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
| Job | no other running task of the organization holds one of its hosts | `host_busy` |
| Sensor | sensor active (not disabled or revoked) | `inactive` |
| Sensor | sensor checking in (online or late) | `offline` |
| Claim SQL | not reserved for another sensor | `pinned_elsewhere` |
| Claim SQL | in the task's scan zone, with the tool | `outside_zone` |
| Claim SQL | the sensor reported the tool installed | `tool_missing` |
| Claim SQL | the sensor has not refused this task | `refused_earlier` |
| Claim SQL | every required capability offered | `capability_missing` |
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
