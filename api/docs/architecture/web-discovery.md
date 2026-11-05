# Web path discovery

Design and decisions: [RFC-150](../rfcs/RFC-150-web-path-discovery.md). The
store side (source `guess`, response evidence) is
[RFC-056 §9](../rfcs/RFC-056-web-attack-surface.md) and
[web-surface.md](web-surface.md).

Path discovery requests paths a web origin never links, chosen by the
platform from the organization's own inventory, with GET and HEAD only, and
records the ones that answer differently from the origin's not-found answer
as endpoints with source `guess`.

## Shipped vs planned

| Part | State |
|---|---|
| Capability `enumerate.web_paths@1` in the stage catalog (tool `webguess`, T1, one origin per task, heavy: 30 days) | shipped |
| Derived candidate list at claim (`internal/app/contentpin/webpaths.go`, `pkg/domain/webendpoint/derived.go`) | shipped |
| Strict web scope with per-host cap (`scope.BuildDiscoveryWebScope`, `WebJobGuard`) | shipped |
| Coverage planning: rule, predicates, switch, budgets, refusals (`internal/app/coverage/path_discovery.go`) | shipped |
| Bug bounty `bruteforce` / `automated_scanning` enforcement for every enumeration job | shipped |
| Coverage gap reasons of discovery and their settlement | shipped |
| `paths` step in Standard recon, Web and Deep recon (optional, Standard depth) | shipped |
| Verification of guessed backup/dump/source/config files | the check is in the sensor (`openctem-backup-file-signature`); wiring planned (RFC-150 §5) |
| Pack lists, recursion, parameter discovery, authenticated discovery | planned |

## How a run is planned

```mermaid
flowchart TD
  L["asset_coverage: enumerate.web_paths on an http_service<br/>every 30d, requires origin_scope_entry,<br/>inventory_changed, edge_clear"] --> S{"organization switch<br/>(scope settings path_discovery)"}
  S -- off --> P1["paused: switched_off"]
  S -- on --> B{"daily request budget left<br/>/ per-origin cap"}
  B -- none --> P2["paused: budget (deferred, never covered)"]
  B -- some --> R{"per target: program forbids<br/>brute force or automated scanning?<br/>address on a shared edge?"}
  R -- yes --> BL["blocked with the reason"]
  R -- no --> C["coverage run: webguess, standard depth,<br/>lists [derived], max_requests = cap"]
  C --> G["web job guard: strict web_scope<br/>GET/HEAD, deny every non-allowed exclusion,<br/>max_requests_per_host"]
  G --> K["claim: program rules (enumeration refused),<br/>content pin: derived list inline"]
```

### Coverage predicates (`internal/infra/postgres/asset_coverage_repository.go`)

| Predicate | Holds when |
|---|---|
| `origin_scope_entry` | an active scope entry names the origin's host: a domain or subdomain entry for a host name, an exact `ip_address` entry for an address |
| `inventory_changed` | the origin has active endpoints first seen since path discovery last succeeded on it (not counting rows it found itself) |
| `edge_clear` | the origin's last `probe.http` or `vuln.templates` outcome is not `edge_challenged` / `edge_blocked` |

A pair whose predicate fails is `not_applicable` with the predicate as the
reason, and becomes due again when it holds.

### Budgets and switches

| Setting | Where | Default |
|---|---|---|
| Organization switch | `PUT /api/v1/scope/settings` `path_discovery` (audited as a scope settings change) | on |
| Per-origin request cap | `PATH_DISCOVERY_REQUESTS_PER_ORIGIN` | 300 (50..100000) |
| Daily requests per organization | `PATH_DISCOVERY_DAILY_REQUESTS` | 50000 |

Deferred and switched-off pairs are `paused` with the readiness reason
`budget` or `switched_off`; they are never marked covered and resume on their
own.

## The derived list

Built at claim from the job's organization's rows only
(`postgres.WebDiscoveryRepository`):

1. backup copies of observed file endpoints: up to 8 of
   `.bak ~ .old .orig .swp .save .tmp .zip` per file, sensitive (catalog)
   files first, then the newest;
2. version siblings of `/v<n>/` paths: every lower version and `v<n+1>`;
3. paths at least two of the organization's other origins serve and this one
   does not, the most widespread first;
4. GET paths the origin's API descriptions declare.

Templated paths, destructive paths (`webpath.Destructive`), paths the origin
already has and paths under a denied exclusion (`webpath.Denied` on
`webpath.CleanPath`, the sensor's reading) are dropped. The classes are
interleaved, the list is truncated to 20,000 lines and the inline cap (256
KiB gzip), and a truncation is logged. An empty list refuses the job with
the reason (nothing to check).

## The job's web scope

`web_scope` of a discovery job:

```json
{"deny_paths": ["/admin"], "methods": ["GET", "HEAD"], "max_requests_per_host": 300}
```

`deny_paths` holds every path exclusion on the target hosts whose testing
mode is not `allowed` (a `read_only` exclusion included). The scope is always
attached, replaces any value the creator wrote, and the cap comes from the
job's `max_requests` (default 300).

## Outcomes

The sensor reports one coverage gap per origin in the task result
(`metadata.coverage_gaps`: `host` the origin, `reason` the primary reason,
`detail` every reason with its count, for example `catch_all=12
scope_filtered=3`; `scope_filtered:<n>` is also accepted). Settlement:

| Reason | Ledger |
|---|---|
| `edge_protected` | failed, edge challenged (target side) |
| `throttled` | failed, rate limited |
| `blocked` | failed, edge blocked |
| `budget`, `hostile_response`, `protocol` | failed, unfinished |
| `catch_all`, `auth_wall`, `unstable_baseline`, `scope_filtered` | covered; the reason stays on the run |

When one origin lists several gaps, a reason that leaves it uncovered wins.
The web console reads these from the run's task view (`coverage_gaps`) and
the origin's coverage row (`/assets/{id}` coverage, capability
`enumerate.web_paths`).

## Bug bounty programs

A job enumerates when its capability (or a required capability word) is an
`enumerate.*` capability, its tool only enumerates (`webguess`, `dnsx-enum`)
or its config asks for `method: bruteforce`. When a program covering its
targets forbids `bruteforce` or `automated_scanning`:

- a single-scanner scan trigger is refused (`PROGRAM_FORBIDS_ENUMERATION`);
- coverage blocks the pair (`program_forbids_enumeration`);
- any job reaching a sensor is failed at claim with the reason
  (`PROGRAM_FORBIDS_ENUMERATION: ...`), on every hand-out path.

## Key files

- `pkg/domain/stage/catalog.go`, `contract.go`, `heavy.go`, `web.go`
- `pkg/domain/webendpoint/derived.go`
- `internal/app/contentpin/webpaths.go`, `internal/infra/postgres/web_discovery_repository.go`
- `internal/app/scope/web.go` (`BuildDiscoveryWebScope`), `web_job.go`
- `internal/app/coverage/path_discovery.go`, `planner.go`
- `pkg/domain/command/enumerate.go`, `internal/app/command/program_rules.go`, `internal/app/scan/program_rules.go`
- `pkg/domain/scanrun/coverage_gaps.go`, `pkg/domain/coverage/settle.go`
- `internal/app/scanrun/path_discovery.go`
- migration `20261105060450_easm_workflow_path_discovery_step`
