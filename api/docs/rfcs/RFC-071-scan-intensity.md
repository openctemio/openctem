# RFC-071: Scan intensity (passive, active, intrusive)

| | |
|---|---|
| Status | Accepted (delegated, 2026-10-10); P0 in implementation |
| Scope | api (`pkg/domain/scan` intensity, `pkg/domain/stage` tool networks, `internal/app/scan` create/trigger, `internal/app/scanrun` step dispatch, `internal/app/command` claim, the dispatch gate's passive scope rule, two migrations), web (New Scan wizard, badges, scope preview) |
| Architecture | [scan-intensity.md](../architecture/scan-intensity.md) |
| Related | RFC-036 (EASM, T0/T1/T2 tiers), RFC-046 (Scan → Run → Task, stage catalogue), RFC-054 (scope model), RFC-055 (tool contract tiers), RFC-068 (dynamic targets), [active-probe-gate.md](../architecture/active-probe-gate.md), [certificate-transparency-monitoring.md](../architecture/certificate-transparency-monitoring.md) |

## 1. Summary

Every scan carries an **intensity** chosen when it is created: **Passive**,
**Active** or **Intrusive**. It is the ceiling of what any run of the scan may
send toward the targets. It is stored on the scan, copied into each run's
context (the audit record of what the run was allowed to do), shown as a badge
everywhere a scan or run appears, and enforced at save, at dispatch and at
claim. Nothing else (scope entries, approvals) is coupled to it: it is the
scan's own ceiling.

| Intensity | Tier | What reaches the target hosts | Typical tools |
|---|---|---|---|
| Passive | T0 | Nothing from our sensors. Only third-party sources (certificate logs, passive DNS, search APIs), DNS through recursive resolvers, vendor/code-host APIs | subfinder, dnsx (recursive resolvers), code and image analysis |
| Active | T1 | Non-intrusive probing: port connects, HTTP requests, safe templates, crawling | naabu, httpx, katana, nuclei (non-intrusive) |
| Intrusive | T2 | Fuzzing, intrusive templates, out-of-band callbacks, custom templates | zap, nuclei with custom templates or interactsh |

## 2. Problem

| Today | Effect |
|---|---|
| A scan has no field saying how loud it may be; the tier comes from whichever tool or workflow step runs | "Discover new assets passively first" cannot be expressed or checked |
| At create, the tier check is skipped for workflows (`refuseTierExceeded` returns early) | A workflow with an intrusive step is saved without anyone choosing that |
| A passive (T0) dispatch skips the tier check and refuses only rejected names | A passive step could resolve any domain on the internet: a free lookup service against arbitrary names |
| dnsx is T0 in the catalog, yet nothing says where its packets go | A custom resolver list (the target's own name server) makes it active while still counted passive |
| No starter workflow is purely passive | The default discovery path always probes |

## 3. Goals and non-goals

Goals: an explicit per-scan ceiling, chosen first in the wizard with plain
explanations; enforcement at save (single scanner and every workflow step), at
dispatch (a step above it never becomes a command) and at claim (a command
above it, or whose tool contract raises it above, is never handed out); the
passive path closed (in-scope names only, non-target tools only); a passive
discovery workflow and a continuous-discovery preset.

Non-goals: approvals or scope-entry tier ceilings (scan approval is a separate
design); sensor-side enforcement of the
egress proxy (declarative; the sensor enforces it).

## 4. Model

`scans.intensity` (`passive | active | intrusive`, NOT NULL, CHECK). Domain:
`scan.Intensity` with `MaxTier()` (0, 1, 2), `Allows(tier)`,
`IntensityForTier`, `EffectiveIntensity()` (unknown or empty = active, never
wider).

The tier a step counts at is `stage.IntensityTier(tool, capabilities,
config)`: the highest of the tool's tier (the highest tier among the stages it
implements), the tier of the stage its capabilities name, and T1 for a DNS
resolution step told to use custom resolvers (`resolvers`, `resolver`, `r`,
...). A step the catalog cannot place counts as T1, never passive.

API: `intensity` on create, update, quick scan, import/export and the scan
response; `intensity` on run responses (from the run context). On create an
omitted intensity takes the tier the scanner or workflow already probes at;
the web always sends one (default Active; discovery presets default Passive).
Update keeps the current intensity unless a new one is sent, and re-checks the
scanner or workflow when either changes.

## 5. Enforcement

1. **Save** (`applyIntensity`): the scanner, or the highest workflow step, must
   fit; otherwise `INTENSITY_EXCEEDED` (400) naming the scanner or step.
2. **Trigger**: a single-scanner run whose tool is above the scan's intensity is
   refused (the row changed behind the service). The run context records
   `intensity` from the scan, never from the trigger's context.
3. **Dispatch** (both step schedulers, scan trigger and run advance): a step
   above the run's intensity is **skipped** with the reason ("this step probes
   at T1, above the scan's passive intensity"); its dependents are skipped as
   blocked; the run still ends. After the planner resolves a capability step to
   a tool, the resolved tool is checked again (a pinned or picked tool may be
   louder than the capability's default): above the ceiling, the step fails
   without a command.
4. **Claim**: every command records `intensity` in its dispatch gate record.
   The claim-time re-check fails a command whose recorded tier is above it
   (`INTENSITY_EXCEEDED`); the per-sensor gate withholds a command whose tier
   on that sensor (`CommandTierFor` with the sensor's tool contract: custom
   templates, interactsh, an operator-installed tool) is above it.

A run with no intensity (a workflow run started without a scan) has no ceiling
here; the dispatch gate and grants apply as before.

## 6. Closing the passive path

- **In scope only.** A passive dispatch (a T0 stage of a chain, a T0 workflow
  step, the claim re-check of either) keeps the relaxed ownership rule (a name
  nobody confirmed yet may be resolved; a rejected one never) and now also
  refuses (`no_entry`) any internet name or address that no scope authority of
  the tenant covers (`UncoveredTargets`: no active scope target, root-domain
  seed or verified domain at or above it). Private and internal names stay
  with the scan zones. A single-scanner T0 run already took the full gate.
- **Non-target tools only.** The platform classifies each stage's network
  (`stage.Network`): `egress-proxy` (third-party sources), `resolver`
  (recursive DNS), `vendor` (code host, registry), `none`, or `targets`. Every
  T0 stage declares a non-target network (catalog test). A passive step whose
  resolved tool reaches its targets (`stage.ToolNetwork`) is refused before a
  command exists. dnsx is `resolver`; with custom resolvers it counts as T1.
  The tool contract accepts `network: resolver`, so sensors can declare it.
- **Sensors.** A passive job goes only to sensors whose grant admits it (tier
  ceiling, target network, as today).

## 7. Passive discovery pipeline

- Starter workflow **Passive discovery**: `discover.subdomains` (passive
  sources, certificate transparency among them) → `resolve.dns` (recursive
  resolvers). Results go through normal ingest, attribution and the review
  queue: new names arrive as candidate or needs_review unless a rule confirms
  them. The platform's certificate-transparency monitor keeps running beside it.
- Starter workflow **Probe new assets**: `scan.ports` and `probe.http` (T1),
  no discovery step.
- **Passive lookups** (T0, `egress-proxy`), part of Passive discovery:
  `lookup.rdap` on the root domains (registrar, registrant organization,
  name servers, dates, from the registry's RDAP service through the IANA
  bootstrap) and `lookup.asn` on the resolved addresses (origin autonomous
  system, holder, announced range, from the public-domain IPtoASN dataset).
  Sensor tools `rdap` and `asn` never request a target host; results are
  attributes of the domain and address. Announced ranges (opt-in
  `include_announced`) arrive as networks held for review.
- **Continuous discovery** preset (wizard): two scans saved together: Passive
  discovery of the root domains, daily, at Passive; and Probe new assets of
  `*.<root>` at Active, daily, with `target_options.new_since_last_run`: each
  run takes only the assets under the root that became in scope since the
  previous successful run (attribution confirmed since then, or first seen
  since then without a record), never a needs_review or rejected name (the
  active gate refuses those regardless). The first run takes every confirmed
  asset.

## 8. Migration

`001940_scan_intensity`: the column with default `active` and CHECK; existing
scans are backfilled with the tier they already probe at (single scanner: its
tool; workflow: the highest step, by tool or capability; unknown counts as
active), so no scan changes behaviour. Down drops the column. The discovery
workflows are seeded by a separate migration with their PR.

## 9. Security

Threat model: a member (or a compromised session) uses the platform to probe
targets louder than intended, or to look up arbitrary third-party domains
"passively"; a sensor claims a job its contract makes louder than the scan
allowed; a crafted trigger context sets a wider intensity.

- The ceiling only narrows: it never allows what the dispatch gate, scope,
  grants or local policy refuse. Unknown values fail closed (active for a
  scan, passive-only for a claim record).
- The run's intensity comes from the stored scan, never the trigger context.
- Passive no longer means unchecked: in-scope names only, non-target tools
  only, every lookup tenant-scoped (`scopeauth.Load(tenantID)`); another
  tenant's entries cover nothing (tested).
- Claim-time checks catch a command whose recorded or contract tier exceeds
  the ceiling.
- Authorization: intensity is part of the scan definition (`scans:write`); no
  new route or permission. Tenant isolation: the column is read and written
  only through the tenant-scoped scan repository (cross-tenant update test).

## 10. Decisions

| # | Decision |
|---|---|
| I1 | Three intensities mapped 1:1 to tiers T0/T1/T2. |
| I2 | Intensity is the scan's own ceiling; it is not compared with scope entries or approvals. |
| I3 | Wizard default Active; discovery presets Passive; API omitted = the tool's tier. |
| I4 | A workflow step above the ceiling is refused at save; at run time it is skipped with its reason. |
| I5 | Passive requires the name in the tenant's scope; dnsx is `resolver`, custom resolvers make it T1. |
| I6 | Backfill to the current tier; no back-compat shim. |
