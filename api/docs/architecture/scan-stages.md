# Scan stages: catalogue, planner and chaining

> Last updated: 2026-10-05. Design: [RFC-046](../rfcs/RFC-046-scans-redesign.md)
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
  001020) records what each platform tool produces, backfilled from the
  catalogue. No API writes it; a DB test keeps it equal to the catalogue.
- **Validation.** `stage.ValidateChain` checks an engine's stages: known
  capabilities, unique ids, `from` naming only earlier stages or the seeds (no
  cycle), and a stage that does not take the seeds must take a type its `from`
  stages produce. It refuses T2 stages until the approval flow exists. The
  engine spec (research/27 P1-1) calls it on save.
- **API.** `GET /api/v1/scans/stages` (`scans:read`) serves the catalogue. It is
  static platform data and reads nothing of the tenant.

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
