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

- `Passive discovery` starter workflow: `discover.subdomains` → `resolve.dns`
  → `lookup.asn`, and `lookup.rdap` on the roots (migration
  `001967_passive_lookup_tools`, version 2 of the template).
- The passive lookups (sensor tools `rdap`, `asn`; `network: egress-proxy`):
  - `lookup.rdap`: registration data of a root domain from its registry's
    RDAP service, found through the IANA bootstrap
    (`data.iana.org/rdap/dns.json`), optionally the registrar's RDAP service
    the registry links to. Stored on the domain (`registrar`, `nameservers`,
    `registered_at`, `expires_at`, `whois`: `registrant_org`,
    `registrant_country`, `rdap_server`, `status`). No person name, e-mail,
    phone or street address is kept.
  - `lookup.asn`: origin autonomous system, holder, country and announced
    prefixes of an address or network, from the public-domain IPtoASN
    dataset (PDDL 1.0), downloaded by the sensor at most once a day and
    looked up locally. Stored on the address (`asn`, `asn_org`, `country`,
    `asn_prefixes`) or network. With `include_announced` the other ranges of
    the system are reported as networks (at most `max_ranges`).
  - Neither ever requests a target host, a host under a target name or an
    address inside a target network, a registrar link or redirect included;
    both use https only.
  - A network a sensor report creates gets an attribution record like an
    internet-facing name (`heldForReviewOnCreate`): needs_review from a scan,
    candidate from an unsolicited report. An existing network without a
    record is left alone.
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
