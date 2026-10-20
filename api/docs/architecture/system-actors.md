# System actors: platform policies act as a named policy

Work the platform starts on its own (continuous coverage, automatic
enrichment) has no person behind it. It is attributed to a **named system
policy**, acts with that policy's **explicit authority**, and queues behind a
person's own work. No user row exists for a policy: it cannot be granted
roles, logged into or deleted.

## Attribution

A coverage or enrichment run is stored as `trigger_type = system` with
`triggered_by = "policy:coverage"` or `"policy:enrichment"`. The runs API
reports it as `trigger: {type: "policy", id: "coverage"}` (a person is
`user`, a schedule `schedule`, an automation `automation`).

## Authority

| Who dispatches | Authority checked at dispatch and at the claim re-check |
|---|---|
| A person (Run now, quick scan, an approved run) | the person's act scope |
| A schedule, a retry or an automation | the scan owner's act scope (the owner of the automation, once an automation starts the scan) |
| A platform policy (`DispatchTargetsInput.SystemPolicy`, `command.DispatchGate.SystemPolicy`) | the tenant's scope entries and the capability's tier, **no member's act scope** |
| Nobody | refused |

`ActScope` with no user in the context, no fallback user and no system policy
is refused (`actscope.ErrActorRequired`): a missing actor never means
unrestricted. At the claim, a job that records an act scope but neither an
actor nor a policy is withheld. An unknown policy name is refused.

The policy of a run is recorded in the run context (`system_policy`) by the
scan trigger from the scan's `managed_by`, never from a caller's context; the
caller's `actor_user_id` and `system_policy` are dropped on every trigger and
on `POST /scan-workflows/runs`, so a caller cannot choose who a run acts as.
The marker never reaches a sensor.

## Queue class

The class of a run's commands is set when they are created and ranked by the
claim (class, then aging of one class per 30 minutes, never into critical,
then round-robin across runs):

| Source | Class |
|---|---|
| A person's own start | `high` |
| Schedule, automation, retry, asset discovery | `normal` |
| Platform policy (coverage, enrichment) | `low` |
| Retest, validation | `critical` (unchanged) |

## Upgrade note

Commands queued before this change by coverage or enrichment carry an act
scope with no actor and no policy; the claim re-check withholds them (they are
short-lived and the next planner pass queues new ones).
