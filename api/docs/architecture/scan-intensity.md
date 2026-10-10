# Scan intensity

> Design: [RFC-071](../rfcs/RFC-071-scan-intensity.md). The gate:
> [active-probe-gate.md](active-probe-gate.md). Stages and tiers:
> [scan-stages.md](scan-stages.md). Targets: [scan-targets.md](scan-targets.md).

A scan's **intensity** is the ceiling of what its runs may send toward the
targets: `passive` (T0), `active` (T1) or `intrusive` (T2). It is the scan's
own choice; nothing else derives from it.

## Where it lives

| Place | What |
|---|---|
| `scans.intensity` | the ceiling (CHECK passive/active/intrusive) |
| run context `intensity` | copied from the scan when the run starts (audit; never from the trigger context) |
| `commands.dispatch_gate.intensity` | copied into every command a run queues; read by the claim |
| API | `intensity` on scan create/update/quick scan/import/export and responses; on run responses |

## The tier of a step

`stage.IntensityTier(tool, capabilities, config)`
(`pkg/domain/stage/network.go`): the highest of the tool's tier, the tier of
the stage its capabilities name, and T1 for a DNS-resolution step with custom
resolvers. Unknown = T1.

## Checks

```
save      applyIntensity (internal/app/scan/intensity.go)
            scanner tier / highest workflow step tier <= intensity, else INTENSITY_EXCEEDED
trigger   refuseRunAboveIntensity (single scanner); run context gets intensity
dispatch  scheduleWorkflowSteps (scan) and advanceRun (scanrun):
            IntensitySkipReason -> step skipped with reason, dependents blocked
          queueStepForExecutionWithSettings -> checkStepIntensity:
            resolved tool above the ceiling -> step fails, no command
            T0 step whose tool reaches its targets -> step fails, no command
claim     scope_recheck.go: recorded tier > intensity -> INTENSITY_EXCEEDED (command failed)
          local_policy.go intensityRefusal: CommandTierFor(type, job, sensor contract)
            > intensity -> withheld from that sensor (rule "intensity")
```

## Passive means in scope and off-target

- `refusePassiveOutOfScope` (`internal/app/scan/dispatch_gate.go`): on a
  `PassiveOnly` dispatch, every internet name or address no scope authority of
  the tenant covers is refused `no_entry` (`ActiveGate.UncoveredTargets`).
- `stage.Network`: `egress-proxy`, `resolver`, `vendor`, `none` (off-target)
  or `targets`. Each T0 stage declares an off-target network
  (`TestCatalog_PassiveStagesDeclareANonTargetNetwork`). `ToolNetwork(tool)` is
  `targets` if any stage of the tool reaches its targets or the tool is unknown.
- The tool contract accepts `network: resolver`.

## Discovery

- `Passive discovery` starter workflow: `discover.subdomains` → `resolve.dns`.
- `Probe new assets` starter workflow: `scan.ports`, `probe.http`.
- `target_options.new_since_last_run` on a `*.<root>` selector: only assets
  confirmed (or first seen without a record) since the previous successful
  run; the active gate still refuses needs_review and rejected names.

## Tests

`pkg/domain/stage/network_test.go`, `internal/app/scan/intensity_test.go`,
`internal/app/scanrun/step_intensity_test.go`,
`internal/app/command/intensity_test.go`,
`tests/unit/command_scope_recheck_test.go` (`JobAboveIntensityIsFailed`),
`internal/app/easm/active_gate_test.go` (`UncoveredTargets`, cross-tenant),
`internal/infra/postgres/scan_intensity_db_test.go` (round trip, cross-tenant
update, CHECK).
