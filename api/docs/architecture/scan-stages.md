# Scan stages: catalogue, planner and chaining

> Last updated: 2026-10-07. Design: [RFC-046](../rfcs/RFC-046-scans-redesign.md)
> §5 (engines and the stage catalogue) and research/27 (scan modes and
> workflows, owner decisions G1–G12). Run model: [scan-lifecycle.md](scan-lifecycle.md).
> Target gate: [active-probe-gate.md](active-probe-gate.md).

A scan runs stages. A stage is one **capability** ("discover.subdomains",
"probe.http") run by one tool. Stages are composed by **typed data**: what one
stage produces becomes what the next consumes, through the inventory and the
per-hop gate. A sensor never feeds another sensor.

## 1. The stage catalogue

`pkg/domain/stage` is the type system of scan composition. It is code-reviewed
platform data: a tenant, a sensor or a report cannot widen it.

| Stage | Inputs → outputs | Tier | Tools (default first) |
|---|---|---|---|
| `discover.subdomains` | domain → domain, subdomain | T0 | subfinder |
| `resolve.dns` | domain, subdomain → domain, subdomain, ip_address (`resolves_to`, `cname_of`) | T0 | dnsx |
| `scan.ports` | domain, subdomain, ip_address, host → ip_address, host, open_port | T1 | naabu |
| `probe.http` | names, addresses, open_port, http_service → http_service, certificate, ip_address | T1 | httpx |
| `crawl.web` | http_service, discovered_url, website → discovered_url | T1 | katana |
| `vuln.templates` | web and network types → findings | T1 | nuclei |
| `dast.web` | web applications → findings | T2 | zap |
| `secrets.code` | repository → findings | T0 | betterleaks, trufflehog, gitleaks |
| `sast.code` | repository → findings | T0 | semgrep, codeql |
| `sca.deps` | repository, container → findings | T0 | trivy, osv-scanner, grype |
| `iac.misconfig` | repository → findings | T0 | checkov, kics, trivy |
| `container.image` | container → findings | T0 | trivy, grype |
| `network_va.connector` | ip_address, host, network → findings | T1 | tenable_sc |

- **Tiers.** T0 sends no traffic to the target beyond DNS (or none at all). T1
  is non-intrusive active checking. T2 is intrusive and needs an approver and
  a verified seed (RFC-036 O3); the P0 router never plans a T2 stage.
- **Types** are stored asset-registry pairs (`configs/asset-types.yaml`); the
  table uses the input names for readability. The catalog names
  `service/http` (input name `http_service`), `service/open_port`,
  `service/discovered_url`, `application/website` and `application/api`;
  matching compares canonical pairs, so a report's `http_service` matches.
- **Fan-out.** Each stage has `max_fanout` (at most the run cap of 10 000) and a
  per-parent cap (5 000 by default: a domain with more subdomains than that is
  a suspected wildcard). An engine may lower a cap, never raise it.
- **Hop limit** (owner decision G5): a derived target is at most 3 discovery
  hops from the run's seeds.
- **Registry outputs (research/27 F3).** `tools.output_types` (migration
  001040) records what each platform tool produces, backfilled from the
  catalogue. No API writes it; a DB test keeps it equal to the catalogue.
- **Validation.** `stage.ValidateGraph` checks a workflow graph against the
  capability contracts (§1.1). Every pipeline save calls it: full save, create,
  and add, update or delete of a step, inside the save transaction. It also
  backs `POST /api/v1/scan-workflows/verify` (`pipelines:write`), which checks a
  draft and stores nothing. A pipeline's steps are the graph
  (`pipeline.StepsGraph`): one node per step and one edge per dependency. A step
  the catalogue places is a capability node, with its tool as the pin. A tenant
  tool with no contract is **opaque**: an edge to or from it is a warning (it
  orders the steps and passes no data). The errors, each anchored to a node or
  an edge (422, `details.errors`):
  - an unknown, planned or cross-cutting capability;
  - a pinned tool that does not implement the node's capability;
  - an empty or duplicate node id, an edge naming a missing step, a self-loop or a cycle;
  - an edge whose port types do not meet, with the adapter that would connect them
    (`subfinder → katana`: "insert HTTP probe");
  - a port named on one side only, or a port the node does not have;
  - derived targets fed into an intrusive (T2) node, which the router never feeds;
  - more than 30 nodes or 120 edges.

  Deleting a step drops it from the other steps' dependencies. Every seeded
  system template passes (integration test).
- **API.** `GET /api/v1/scans/stages` (`scans:read`) serves the catalogue with the
  capability contracts (§1.1). It is static platform data and reads nothing of
  the tenant.

### 1.1 Capability contracts (typed ports, params, versions)

Each catalogue stage is a **capability** with a contract (`pkg/domain/stage/contract.go`)
that every implementation honors, so a workflow is wired once and any conforming
tool runs it:

- **Version.** A capability has a versioned id (`scan.ports@1`). Changing its
  ports, removing a param or adding a required output field bumps the major.
- **Typed ports.** Inputs and outputs are also expressed as **port types**, a closed set of ten:
  `root_domain`, `hostname`, `ip`, `cidr`, `service`, `url`, `repository`,
  `container_image`, `cloud_account` and `finding`. Each port type carries stored
  pairs (`url` carries `service/http`, `service/discovered_url`,
  `application/website` and `application/api`). An edge connects an output
  port to an input port of the same type. The stored `Inputs`/`Outputs` stay
  what the router and the output binding use. A unit test keeps the ports and
  the stored types equal: each type a stage takes or produces is carried by
  one of its ports, and each port carries a type the stage takes or produces.
  Technology is an attribute of `url`/`service`, not a port type.
- **Standard params** have a type (`string`, `string_list`, `integer`, `boolean`,
  `port_list`), an optional enum and optional bounds. Each implementation maps
  the params it accepts to its own config key, the key the sensor's settings
  schema declares (naabu: `top_n` → `top_ports`). A tool with no mapping for
  a param does not accept that param.
- **Required output fields** are what a report of the capability must carry.
- **Batch.** Each implementation states whether the tool takes a list of
  targets per task (`stage.AcceptsTargetList`). This replaces the scan
  package's hardcoded scanner map. The Tenable bridge names, which are not catalogue
  tools, keep their entry.
- **Adapters.** One table says which capability turns one port type into another
  (`hostname → url`: `probe.http`; `hostname → ip`: `resolve.dns`;
  `ip → service`: `scan.ports`; …). The editor offers it when two incompatible
  ports are wired.
- **Taxonomy v1** lists 22 capabilities. The 13 routed stages above have
  implementations. Nine are **planned**: they have a contract but no routed
  implementation (`intel.passive`, `check.takeover`, `detect.services`,
  `fingerprint.tech`, `check.tls`, `capture.screenshot`, `host.credentialed`,
  `cloud.posture`, `verify.finding`). They are served with `available: false`
  and are invisible to `Lookup`, `ForTool` and `ForCapabilities`, so no step
  can run one and no tool's routing changes. `verify.finding` is
  cross-cutting (retests), never a workflow node.

`GET /api/v1/scans/stages` serves every capability with its contract and
implementations, plus `port_types` and `adapters`.

**Tool Contract v1** ([RFC-055](../rfcs/RFC-055-tool-contract-v1.md),
[tool-contract.md](tool-contract.md)) moves the contracts to one shared
source, the `github.com/openctemio/ctis/capability` taxonomy, which the SDK
and the sensor read too. The taxonomy keeps every id above. It adds:
- phase and CTEM stage;
- ATT&CK, D3FEND and CAPEC references;
- required output as CTIS path rules, in place of the abstract field names;
- `discover.cloud`, `sbom.generate` and `import.file`.

Tools then declare `implements: [{capability: scan.ports@1, params: …}]` in
their descriptor. The per-tool maps in `contract.go` (`toolParams`,
`batchTools`) and `pipeline.stepToolSettings` become descriptor lookups
behind the same functions. A built-in name fallback stays for sensors
without descriptors, for one release train.

### 1.2 Capability nodes: tool selection and settings

A pipeline step is a **capability node**. It names a capability and picks its
tool in one of three ways (`tool_selection` on the step response):

- **auto** (no tool, no `prefer_tools`): any implementation of the capability,
  in catalog order, with the default first;
- **prefer** (`prefer_tools`, migration 001176): the listed tools, in that
  order. Each must implement the capability;
- **pin** (`tool`): that tool only (strict, G10).

A pin and a prefer list together are refused.

Settings (`config`) follow the contract:

- **Standard params** are checked against their type, enum and bounds on every
  save. Each tool receives them under its own config key. A tool that does not
  take a standard param the step sets is **not eligible** for the node: the planner
  skips it and says why (`NO_MATCHING_TOOL`), and never drops the value silently.
- **Tool extras** go under `x.<tool>`, and only on a step pinned to that tool. On a
  pinned step a plain key is also the pinned tool's own setting, as before
  capabilities.
- On an auto or prefer step, any other key is refused: it would reach only some
  of the tools the platform may pick. `exclude` is read by the executor for
  every tool.

When a step is queued, its step run records the **capability it ran**
(`scan_run_steps.capability`, for example `scan.ports@1`) and the **tool the planner
picked** (`scan_run_steps.tool`). The tier of a capability node is the tier of its
capability: every built-in implementation shares it.

### 1.3 Starter workflows

Migration 001201 seeds five system workflows built only from capability steps
(no pinned tool), so any available implementation runs them:

| Workflow | Steps |
|---|---|
| Discover | `discover.subdomains` → `resolve.dns` → `probe.http` |
| Discover + Vuln | `discover.subdomains` → `resolve.dns` → `scan.ports` → `probe.http` → `vuln.templates` (fed by the probe and the ports) |
| Web app | `probe.http` → `crawl.web` → `vuln.templates` |
| Network | `scan.ports` → `probe.http` → `vuln.templates` |
| Code / CI | `secrets.code`, `sast.code`, `sca.deps` and `iac.misconfig`, in parallel |

They are tagged `starter`. The new-scan wizard offers them first, next to a
single check. An integration test checks that each passes the graph check
and resolves a seeded platform tool for every step. The presets they replace
are deactivated, not deleted.

### 1.4 Workflow preview

`POST /api/v1/scans/workflow-preview` (`scans:write`) answers what a workflow
scan would do if it started now, without creating anything
(`internal/app/scan/workflow_preview.go`):

- **Per step:** the capability, the tier, the tool `ResolveStepTool` picks, and the
  tool's sensor availability in the scan's zone. The step is blocking when the
  trigger's `NO_SENSOR_FOR_TOOL` check would refuse it. The code and message are
  the trigger's, and a unit test asserts this parity.
- **Targets:** the zone routing preview with scan type `workflow`, which runs the
  trigger's target resolution, scope exclusions and zone plan. The sample is cut
  to 20 targets.
- **Freeze:** a freeze window active now for the scan's zone, for active work.

The workflow must be the organization's own or a system workflow (otherwise
404). The new-scan wizard shows the preview on its last step.

## 2. The planner: one dispatcher, capability → tool

Every pipeline step command is built on one path:
`pipeline.Service.queueStepForExecutionWithSettings`. The scan trigger hands a
workflow's first steps to it (`scan.StepQueuer`, wired as
`s.Scan.SetStepQueuer(s.Pipeline)`); unwired, a workflow scan is refused. The
payload comes from one builder, `scan.StepCommandPayload`.

- **F1 (research/27).** A step that named only a capability passed validation
  but its command carried no `scanner`, so the sensor failed it with
  `scanner not found: `. `scan.ResolveStepTool` now decides the tool, with the
  same rule for validation (scan trigger and pipeline template checks) and
  dispatch, and the payload always names it in `scanner` and
  `preferred_tool`.
- **Resolution (owner decision G10).** A pinned tool is strict. A capability
  that names one catalogue stage (`scan.ports`, or a word such as
  `portscan`) runs the first active platform implementation of the stage,
  the default first; a collector or connector is never picked; none active is
  `NO_MATCHING_TOOL`. Capabilities naming several stages are refused
  (`STEP_CAPABILITY_AMBIGUOUS`), never guessed. Capabilities the catalogue
  does not know fall back to the tenant's tool lookup (tenant-scoped, platform
  tools first). Platform implementations are read with
  `GetPlatformToolByName`, never another tenant's tool of the same name.
- **F2.** A step condition the scheduler cannot evaluate (`expression`, or a
  type this version does not know) never passes; the step is skipped with
  "Condition type ... cannot be evaluated". `SetCondition` already refused
  expressions; this covers rows stored before that check.
- **Own sensors only.** A scan with `run_on_tenant_runner` carries
  `tenant_runner_only` in its run context; the dispatcher never sends any of
  its steps to platform sensors, whatever the template prefers. (Steps after
  the first used to ignore it.)
- **No step is pinned to one sensor** (research/49 W27). A step command goes
  to the run's zone (stamped with it), to the platform queue, or to the
  tenant's sensors, and is left unpinned: the claim predicates (zone, tool,
  grant, refusals, freeze) decide which sensor takes it. `SelectSensor` only
  decides platform versus tenant now; it no longer picks a sensor.
- **Chunks.** A step whose tool takes a target list (the catalogue's `batch`
  flag) and whose planned targets exceed its capability's `chunk_size` is cut
  into chunks of that size, one unpinned command each, all naming the step
  run. Every eligible sensor takes a share by pull, a lease that runs out puts
  a chunk back in the pool for another sensor, and the step settles with its
  last chunk through the batch logic (`checkStepBatches`: every chunk failed
  means failed, some failed means partial). Sizes come from the capability
  contract, not from the tool: `resolve.dns` and `probe.http` 200,
  `discover.subdomains` and `scan.ports` 50, `vuln.templates` 25,
  `crawl.web` and `dast.web` 10; the code, image and connector capabilities
  are not cut. A one-target tool keeps one command per step. If a later
  chunk cannot be created, the ones already created are canceled.
  Where the chunks went: `GET /scan-runs/{id}/stages` gives each stage
  its chunk counts by state and the share of each tenant sensor that took
  one (`StepSensorShares`, tenant-scoped; platform jobs are counted as
  platform without the platform sensor's identity). The run panel shows them
  per lane and on the workflow graph, and the workflow preview shows each
  step's chunk size and how many sensors can work on it at once
  (`max_parallel_sensors`: every online eligible sensor for a chunked step,
  one otherwise).
- **One sensor per host** (platform-side politeness, migration 001186). A
  chunk of an active stage (T1 and above) records the hosts it sends traffic
  to in `commands.host_keys` (lower-case name or address, no scheme, port or
  path). The poll offers, and a claim takes, such a chunk only while no other
  acknowledged or running command of the tenant holds one of its hosts
  (`hostFreePredicate`). Claims serialize on the keys with transaction
  advisory locks (`lockHostKeys`), and a batch claim takes one chunk per
  host. Only acknowledged and running commands count, so a finish, a failure,
  a release or an expired lease frees the hosts with nothing to clean up.
  Passive stages carry no keys. Keys are tenant-scoped, so another tenant's
  work never holds a tenant back. The sensor's own `PerHostConcurrency` stays
  as defense in depth. Platform jobs (`get_next_platform_job`) do not check
  host keys yet.
  Not yet: the candidate tool list per chunk (claim by any candidate),
  placement modes and a spread cap (research/49 §3.12.3).

## 4. Report output-type binding (owner decision G12)

`internal/app/ingest/output_binding.go`. A report bound to a command may
carry only the asset types its tool is declared to produce or take: the
outputs of the tool's catalog stages plus the inputs it re-observes
(`stage.MayReport`). This stops a compromised or buggy sensor from planting
arbitrary assets through a legitimate command (research/22b S2), and it is
what makes chained outputs trustworthy.

- **Quarantine mode** (the default for a tenant with no stored policy): the
  out-of-contract assets, and the findings that name them, are stored in the
  sensor result quarantine with reason `out_of_contract` and are not
  applied; the rest of the report is. If the quarantine cannot take them they
  are dropped, never applied.
- **Warn mode** (existing tenants, as set by #889): the report is applied
  whole; the tenant audit log records what was out of contract.
- An unclassified type is out of every contract. A tool the catalog does not
  know (a tenant's custom tool) has no catalog contract; unsolicited reports
  keep their own gate.
- **Declared produces.** A tool ported to the tool contract (sdk-go
  `docs/rfcs/sensor-sdk-v2.md`) declares what it produces (`asset:<type>`,
  `finding:<type>`, `dependency`) in its sensor's current manifest
  (`tools[].contract`, see [sensors.md](sensors.md#tool-contracts)). That
  declaration narrows the binding further: an asset, a finding or a
  dependency of an undeclared type is out of contract too, also for a tool
  the catalog does not know, and also in a report without assets. It never
  widens: when the catalog knows the tool, an asset must pass both. The
  declaration is read from the manifest of the sensor that submitted the
  report, under that sensor's tenant, so another tenant's sensor never
  contributes one. A sensor without contracts, or a manifest that cannot be
  read, leaves the catalog contract as the only rule.
- Every case writes a `sensor.results_quarantined` audit entry (reason,
  tool, counts, type labels) and a metric.

## 3. The hop router: chaining with a gate at every hop

`internal/app/pipeline/hop_router.go`; tables `scan_step_outputs`,
`scan_run_stage_plans`, `scan_run_targets` (migrations 001048, 001049).

- **E6.** A step used to receive the run's seeds whatever came before it. Now,
  when a step's direct predecessors produce asset types its stage takes (and
  produced results: `completed` or `partial`), its targets are the seeds plus
  what those predecessors produced, after the gate.
- **Data flows through the inventory only (G3).** Ingest records the assets
  each command-bound report wrote (`scan_step_outputs`), keyed by the step run
  the command names server-side (`commands.scan_run_step_id`, now set on every step
  command). A sensor's raw output is never read, and a sensor cannot attribute
  output to another step, run or tenant.
- **Stage barrier (G4).** A chained stage is planned once its predecessors
  finished **and** no v2 report of their commands is still open. A pending
  report defers the step; the v2 commit calls `OnCommandIngested`, which
  advances the run. (A report that expires uncommitted wakes nothing: the run
  timeout ends such a run; P1 adds a sweep.)
- **The per-hop gate.** Each candidate: the stage takes its stored pair; the
  name parses strictly (host, IP, host:port or an http(s) URL without
  credentials; no control or bidi characters; at most 2 048 characters);
  hop ≤ 3 (G5); per-parent and per-stage caps; then `scan.ResolveDispatchTargets`,
  the one gate of every active path: target validator (internal, metadata and
  link-local addresses), scope exclusions, act scope of the run's actor (the
  person who triggered it, else the scan owner), zone routing (a chained
  step never leaves its run's zone), and the ownership gate. A **T0** stage
  runs it with `PassiveOnly`: only rejected names (tombstone, rejected record,
  rejected parent) are refused, so a `needs_review` name may be resolved. A
  **T1** stage takes only what `easm.ActiveGate` allows. A **T2** stage is
  never fed derived targets (`STAGE_NOT_CHAINABLE`).
- **Hops (research/30 V3).** A hop counts only when the chain reaches a new
  name: a port, service or URL on a host the run already reached keeps that
  host's hop; a subdomain of a parent name is one hop further; a resolved
  address or alias is one hop beyond the furthest parent. So a six-stage
  chain on one host stays within the limit.
- **Exactly once.** `scan_run_stage_plans (run_id, stage_key)` is claimed in
  the same transaction that records the targets; a duplicate completion or
  ingest event plans nothing.
- **No inputs.** A chained stage left with no target is settled `completed`
  without a command, with `no inputs: ...` and the counts, and the run moves on.
- **Provenance and lanes.** `scan_run_targets` keeps one row per (run, stage,
  target): seed or derived, parent asset and stage, relation (`same_host`,
  `subdomain_of`, `derived`), hop, and the rule that allowed it
  (`seed`, `passive_allowed`, `gate_allowed`) or why it was skipped
  (`excluded`, `unconfirmed`, `refused`, `other_zone`, `hop_limit`,
  `over_cap`, `duplicate`, `invalid`). `GET /api/v1/scan-runs/{id}/stages`
  (`pipelines:read`, tenant-scoped, counts only) serves the per-stage counts.
- **Tenant isolation.** Every query is scoped to the run's tenant, and every
  row references the run and assets with composite tenant foreign keys, so a
  cross-tenant row is refused by the database. Asset merges move these rows to
  the kept asset.
