# Scan stages: catalogue, planner and chaining

> Last updated: 2026-10-14. Design: [RFC-046](../rfcs/RFC-046-scans-redesign.md)
> §5 (engines and the stage catalogue; scan modes and workflows, decisions
> G1–G12). Run model: [scan-lifecycle.md](scan-lifecycle.md).
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
| `resolve.dns` | domain, subdomain → domain, subdomain, ip_address (`resolves_to`, `cname_of`); wildcard-DNS filter on (RFC-088 §8) | T0 | dnsx |
| `lookup.rdap` | domain → domain (registrar, registrant organization, name servers, dates) | T0 | rdap |
| `lookup.asn` | ip_address, network → ip_address, network (origin AS, holder, announced range) | T0 | asn |
| `discover.hosts` | ip_address, network → ip_address (live, with the probe that answered) | T1 | naabu (only for a step that names the capability) |
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
- **Hop limit** (decision G5): a derived target is at most 3 discovery
  hops from the run's seeds.
- **Registry outputs.** `tools.output_types` (migration
  001040) records what each platform tool produces, backfilled from the
  catalogue. No API writes it; a DB test keeps it equal to the catalogue.
- **Validation.** `stage.ValidateGraph` checks a workflow graph against the
  capability contracts (§1.1). Every scan workflow save calls it: full save, create,
  and add, update or delete of a step, inside the save transaction. It also
  backs `POST /api/v1/scan-workflows/verify` (`scans:workflows:write`), which checks a
  draft and stores nothing. A scan workflow's steps are the graph
  (`scanrun.StepsGraph`): one node per step and one edge per dependency. A step
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
- **Implementations come from the tools' contracts.** Which tools implement
  a stage is not in `pkg/domain/stage`: it is the organization's
  `stage.Catalog`, built from the tool contracts its sensors and the
  platform's sensors report ([tool-contract.md](tool-contract.md) §2.1). A
  tool no reported contract names implements nothing; a step that pins it by
  name still runs it, as a tenant tool that never chains.
- **Standard params** have a type (`string`, `string_list`, `integer`, `boolean`,
  `port_list`), an optional enum and optional bounds. Each implementation maps
  the params it accepts to its own config key, from its descriptor's
  `implements[].params` (naabu: `top_n` → `top_ports`). A tool with no
  mapping for a param does not accept that param.
- **Required output fields** are what a report of the capability must carry.
- **Primary capability.** The first capability a tool's contract implements
  is its primary one; it runs any other only for a step or job that names
  that capability (`Implementation.ByCapability`). naabu implements
  `scan.ports` then `discover.hosts`; a step that pins naabu without naming
  `discover.hosts` (every existing naabu step and quick scan) is a port scan,
  and a report that names no capability is bound to `scan.ports`.
- **Batch.** Each implementation states whether the tool takes a list of
  targets per task (`Catalog.AcceptsTargetList`, the contract's
  `input.batch`). The Tenable bridge names, which report no contract, keep
  their entry in the scan package.
- **Adapters.** One table says which capability turns one port type into another
  (`hostname → url`: `probe.http`; `hostname → ip`: `resolve.dns`;
  `ip → service`: `scan.ports`; `cidr → ip`: `discover.hosts`; …). The editor offers it when two incompatible
  ports are wired.
- **Taxonomy v1** lists 22 capabilities. The 13 routed stages above have
  implementations. Nine are **planned**: they have a contract but no routed
  implementation (`intel.passive`, `check.takeover`, `detect.services`,
  `fingerprint.tech`, `check.tls`, `capture.screenshot`, `host.credentialed`,
  `cloud.posture`, `verify.finding`). They are served with `available: false`
  and are invisible to `Lookup`, `ForTool` and `ForCapabilities`, so no step
  can run one and no tool's routing changes. `verify.finding` is
  cross-cutting (retests), never a workflow node.

`GET /api/v1/scans/stages` serves every capability with its contract and the
caller's organization's implementations (the tenant comes from the
authenticated principal), plus `port_types` and `adapters`.

**Tool Contract v1** ([RFC-055](../rfcs/RFC-055-tool-contract-v1.md),
[tool-contract.md](tool-contract.md)) moves the contracts to one shared
source, the `github.com/openctemio/ctis/capability` taxonomy, which the SDK
and the sensor read too. The taxonomy keeps every id above. It adds:
- phase and CTEM stage;
- ATT&CK, D3FEND and CAPEC references;
- required output as CTIS path rules, in place of the abstract field names;
- `discover.cloud`, `sbom.generate` and `import.file`.

Tools declare `implements: [{capability: scan.ports@1, params: …}]` in
their descriptor. The planner reads those declarations: the per-tool param,
batch and capability-job maps are gone from `pkg/domain/stage`, which keeps
only a default preference order per capability. A sensor that reports no
contract contributes no implementation.

### 1.2 Capability nodes: tool selection and settings

A scan workflow step is a **capability node**. It names a capability and picks its
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
| Network | `discover.hosts` → `scan.ports` → `probe.http` → `vuln.templates` (Host discovery added by migration `network_workflow_host_discovery`) |
| Code / CI | `secrets.code`, `sast.code`, `sca.deps` and `iac.misconfig`, in parallel |

They are tagged `starter`. The new-scan wizard offers them first, next to a
single check. An integration test checks that each passes the graph check
and resolves a seeded platform tool for every step. The presets they replace
are deactivated, not deleted.

#### Template updates

A tenant's copy of a system workflow keeps its lineage
(`scan_workflows.source_template_id` and `source_spec`, migration
`workflow_template_lineage`): the template it was made from and that
template's settings and steps as the copy last took them (the base). Both
clone paths record it. Copies made before the lineage existed got it from the
audit event of the copy (same tenant) or, without one, from a system template
whose name they have ("Network", "Network (Copy)") when they share a step
key. Their base is their own steps.

When the template changes (a migration adds Host discovery to Network, for
example), `GET /scan-workflows/{id}/template-update` offers the copy the
changes since the base that it can take (`scanworkflow.TemplateChanges`):

- a step the template added that the copy does not have (`add_step`);
- the dependencies of a step the template rewired, when the copy's step
  still depends on what the base had (`depends_on`).

A step the template removed, renamed or reconfigured is not offered: the
copy's step is the tenant's. The builder shows "Update available: add Host
discovery" with a preview of each change. `POST .../template-update/apply`
(scan workflows write) applies it like a published draft: checked, steps
replaced in place, version moved on and pinned, the base moved to the
template, audited (`scan_workflow.updated` with `template_update: applied`
and the changes). It is refused while the copy has an unpublished draft and
when the template changed since the preview (`template_digest`, 409).
`POST .../template-update/reject` keeps the copy and moves the base
(audited). A tenant workflow is never changed without one of these calls;
every lookup is by the caller's tenant (another tenant's copy is not found)
and the source must be a system template.

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
- **Scan windows:** `targets.windows`, the targets that wait for their scan
  windows and until when, at the workflow's highest tier; a target whose
  windows never open blocks (`SCAN_WINDOW_NEVER_OPENS`).

The workflow must be the organization's own or a system workflow (otherwise
404). The new-scan wizard shows the preview on its last step.

## 2. The planner: one dispatcher, capability → tool

Every scan workflow step command is built on one path:
`scanrun.Service.queueStepForExecutionWithSettings`. The scan trigger hands a
workflow's first steps to it (`scan.StepQueuer`, wired as
`s.Scan.SetStepQueuer(s.Pipeline)`); unwired, a workflow scan is refused. The
payload comes from one builder, `scan.StepCommandPayload`.

- **F1.** A step that named only a capability passed validation
  but its command carried no `scanner`, so the sensor failed it with
  `scanner not found: `. `scan.ResolveStepTool` now decides the tool, with the
  same rule for validation (scan trigger and scan workflow checks) and
  dispatch, and the payload always names it in `scanner` and
  `preferred_tool`.
- **Resolution (decision G10).** A pinned tool is strict. A capability
  that names one catalogue stage (`scan.ports`, or a word such as
  `portscan`) runs the first active implementation of the stage in the
  organization's catalog, the default first; a collector or connector is never picked; none active is
  `NO_MATCHING_TOOL`. Capabilities naming several stages are refused
  (`STEP_CAPABILITY_AMBIGUOUS`), never guessed. Capabilities the catalogue
  does not know fall back to the tenant's tool lookup (tenant-scoped, platform
  tools first). Implementations are read with the tenant-aware
  `GetByName` (the platform tool, else the organization's own declared
  tool), never another tenant's tool of the same name.
- **Target kinds (RFC-088).** After the type gate, every target of a step
  goes only to a stage that takes its kind (`stage.AcceptsKind`): a name, an
  address, a network range, a URL or a service. A typed-in target is
  decided by its kind; an inventory target by its stored type, except a
  range, which is decided by kind whatever its type. A range reaches only
  `scan.ports` (which expands it itself) and network lookups
  (`lookup.asn`, connector network scans); never `probe.http`,
  `crawl.web` or `vuln.templates`. A step left with nothing fails with
  `INCOMPATIBLE_TARGETS`; a chained step keeps an empty seed list. A
  single-scanner scan applies the same rule for its scanner's stage and
  counts what it left out as incompatible.
- **F2.** A step condition the scheduler cannot evaluate (`expression`, or a
  type this version does not know) never passes; the step is skipped with
  "Condition type ... cannot be evaluated". `SetCondition` already refused
  expressions; this covers rows stored before that check.
- **Own sensors only.** A scan with `run_on_tenant_runner` carries
  `tenant_runner_only` in its run context; the dispatcher never sends any of
  its steps to platform sensors, whatever the template prefers. (Steps after
  the first used to ignore it.)
- **No step is pinned to one sensor.** A step command goes
  to the run's zone (stamped with it), to the platform queue, or to the
  tenant's sensors, and is left unpinned: the claim predicates (zone, tool,
  grant, refusals) and the scan window hold decide which sensor takes it and when. `SelectSensor` only
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
  are not cut. An active capability with an address budget also closes a
  chunk before its addresses would pass the budget (`scan.ports`: 1 024
  addresses, `discover.hosts`: 4 096 addresses in chunks of at most 64
  targets; RFC-088 §6): a range piece weighs its address count, any other
  target 1, and a target heavier than the budget gets a chunk of its own.
  The target gate cuts every range into pieces of at most /24 (IPv6 /120),
  so a /16 port scan is 64 chunks of four /24s that every eligible sensor
  shares. A one-target tool keeps one command per step. If a later
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
  (`hostFreePredicate`). Addresses and ranges know about overlap (RFC-088
  §6): an address chunk also holds an `in:` marker of its /24 (IPv6 /120)
  bucket, a range piece holds the `net:` key of each bucket it covers, and
  a chunk waits while another holds a key it conflicts with
  (`command.HostKeyConflicts`): the same name or address, or a range and an
  address in its bucket, either way round. Two addresses of one bucket still
  run in parallel. Claims serialize on the keys with transaction
  advisory locks (`lockHostKeys`; a bucket marker and a range key of the
  same bucket share one lock), and a batch claim takes one chunk per host
  and never a range with an address inside it. A platform sensor's claim
  (`get_next_platform_job`, migration `platform_jobs_host_keys`) applies the
  same predicate and the same bucket locks, then checks again, so a platform
  sensor and a tenant sensor never take overlapping hosts at once. Only acknowledged and running commands count, so a finish, a failure,
  a release or an expired lease frees the hosts with nothing to clean up.
  Passive stages carry no keys. Keys are tenant-scoped, so another tenant's
  work never holds a tenant back.
  **Every command, one choke point** (research/130). `CommandRepository.Create`
  gives every command its keys (`command.AssignHostKeys`), whatever path
  built it: a single-scanner or quick scan, a zone fan-out, validate,
  retest, a platform job. Keys the caller set (a scan run's stage-aware
  keys) win, then a payload's own `host_keys`, else the keys of the
  payload's `target` and `targets` in its `network_id`: exactly the keys a
  sensor computes when none are sent, less the keys of local filesystem
  paths (a code scan of `.` or `/src` is on the running sensor's own disk
  and never holds another sensor back). They are written into the payload
  too, so the two sides never disagree. A follow-up of unfinished targets
  holds only the keys of its remaining targets among its parent's. A
  startup pass (`BackfillPendingHostKeys`) keys pending commands queued
  before this rule, in the column only: their payloads stay exactly as
  queued. Only `Create`, the follow-up and the window-hold copy
  insert commands (a test fails on any other `INSERT INTO commands`).
  **One key function on both sides** (RFC-090): the keys are computed by
  `github.com/openctemio/ctis/politeness` (the CTIS contract), which the sensor runtime
  uses too, and every catalog-stage chunk carries the keys the platform
  holds for it in its payload (`host_keys`; an empty list for a passive
  stage). The sensor's local per-host limit (`limits.per_host_concurrency`,
  default 1) admits the chunk under exactly those keys with the same
  conflict relation, so it never hands back a chunk the platform has just
  offered because the two keyed a host differently (the "its hosts are busy
  on this sensor" loop). Addresses are canonical (an IPv4-mapped address is
  the IPv4 address; `a.b.c.d/32` is the address). With a network context
  (RFC-089) the keys of private addresses and names carry the network, so
  overlapping private ranges at two sites never hold each other back;
  public addresses never do.
  **Hosts are released per target** (research/130, migration
  `command_settled_host_keys`). A running command holds a host only while
  one of its pending targets needs it. The sensor's local queue tracks each
  held command with `politeness.Holding` (ctis): when the job reports a
  target done, the keys no pending target produces are freed on the sensor
  and named on the next heartbeat (`progress.<id>.released_keys`).
  `RecordProgress` adds them to `commands.settled_host_keys`, only for a
  command that sensor holds and only keys of that command, and they only
  grow within a claim; every claim resets them. A holder counts against a
  pending command only through a conflicting key it has not released
  (`holdsUnsettledSQL`, also in `get_next_platform_job`), so the next
  tool's work on a host starts as soon as this one is done with it. A
  bucket marker stays held while a pending address of the bucket does. Poll
  cost, measured on 300k commands with 2,200 running holders (70 keys each,
  half with released keys) and 5,000 pending commands of one tenant: the
  per-row host probe stays one GIN bitmap scan (about 0.05 ms), and the
  release check adds no measurable time.
  Not yet: the candidate tool list per chunk (claim by any candidate),
  placement modes and a spread cap.

## 4. Report output-type binding (decision G12)

`internal/app/ingest/output_binding.go`. A report bound to a command may
carry only the asset types its tool is declared to produce or take: the
outputs of the tool's catalog stages plus the inputs it re-observes
(`stage.MayReport`). This stops a compromised or buggy sensor from planting
arbitrary assets through a legitimate command, and it is
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

`internal/app/scanrun/hop_router.go`; tables `scan_step_outputs`,
`scan_run_stage_plans`, `scan_run_targets` (migrations 001048, 001049).

- **Seeds** are the run's targets as resolved at its start, including what a
  wildcard or inventory-mode CIDR selector expanded to from the inventory
  ([scan-targets.md](scan-targets.md)); a `discover.subdomains` step takes
  only the apex of a wildcard selector.
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
- **Hops.** A hop counts only when the chain reaches a new
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
  (`scans:read`, tenant-scoped, counts only) serves the per-stage counts.
- **Tenant isolation.** Every query is scoped to the run's tenant, and every
  row references the run and assets with composite tenant foreign keys, so a
  cross-tenant row is refused by the database. Asset merges move these rows to
  the kept asset.
