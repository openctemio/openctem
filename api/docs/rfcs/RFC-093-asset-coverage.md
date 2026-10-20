# RFC-093: Asset coverage — every asset gets every capability its type needs, and a gap is never silent

| | |
|---|---|
| Status | Accepted (2026-10-14). P0 in implementation: coverage policy in the registry, the coverage ledger, due marking at ingest, the coverage planner, gap detection, the explanation endpoint |
| Scope | api (asset registry, ingest, scan planner, notifications, settings), web (asset coverage panel, settings) |
| Related | RFC-042 (asset registry), RFC-046 (stage catalog), RFC-054 (scope model, unclassified assets), RFC-068 (dynamic targets), RFC-075 (asset freshness), RFC-088 (scope-aware target allocation), RFC-089 (reachability), RFC-090 (work pool), RFC-092 (tool-agnostic platform) |

## 1. Summary

Scanning is driven by scans today: a person picks targets, and a workflow
chains its stages once per run. When a stage fails, is refused or produces
nothing, the assets it should have fed are never offered again, and nothing
says so. This RFC makes coverage asset-centric:

- the **registry** says which capabilities each asset type needs and how
  often (`coverage:` in `configs/asset-types.yaml`);
- one **ledger**, `asset_coverage`, keeps per asset, capability and vantage
  the state, the last attempt and success, the outcome, the reason and the
  next due time;
- **ingest** marks the affected ledger rows due in the transaction that
  writes the assets, so a new or changed asset is never lost;
- a **planner** turns due rows into work for the tenant's continuous
  coverage scan through the one scope gate and the normal dispatch path;
- two **gap detectors** alert when a required pair stays uncovered for more
  than twice its cadence, or when a capability stops producing what it
  should;
- an **explanation endpoint** answers, per asset, what was done, what is due
  and why something was skipped.

Workflows and quick scans keep working and settle the same ledger.

## 2. Problem (measured on a live installation, 2026-10-14)

- 92 of 94 open web ports were never HTTP-probed as `address:port`.
- No web origin asset existed, although the HTTP probe completed twice: its
  results were folded into the subdomain rows (fixed separately).
- 292 derived targets were refused as unconfirmed; 288 were confirmed later
  and never offered again.
- 34 of 105 subdomains were never a target of the port, HTTP or template
  stages; no address was ever a port-scan target of its own.
- None of this raised an alert.

## 3. Decisions (owner, 2026-10-14)

| # | Decision |
|---|---|
| D1 | Active coverage runs automatically for assets the scope gate allows, on by default, audited. Strict-governance tenants are off until they enable it. DAST and default-credential checks are never on by default. |
| D2 | Default policy: the `coverage:` blocks of the registry (domain, subdomain, address, open port, web origin first). |
| D3 | Workflows stay as presets that settle the same ledger; scheduled workflow scans are retired once the planner covers every capability. A tool swap does not make rows due; a content change does. |
| D4 | Tenant administrators get per-tenant coverage gaps; the platform operator gets fleet-wide output drops as aggregates with no tenant identity. A gap is a pair uncovered for more than twice its cadence; an output drop is zero outputs over at least 20 inputs, or 3 consecutive failed attempts. |

## 4. Coverage policy

Each registry type may list rules:

```yaml
coverage:
  - { capability: probe.http, every: 3d, requires: [web_port], expects: http_service }
```

- `capability` is a stage catalog key or a platform check (`dns.dangling`,
  `dns.email`). A test proves each stage takes the type and may produce the
  expected output.
- `every` is `<n>h` or `<n>d` within [1 h, 30 d].
- `requires` is a closed set of predicates over stored facts: `resolves`,
  `web_port`, `scope_entry`. No expression language.
- `expects` is the type a successful run must produce for the asset; it
  drives the output check.
- A policy never widens scope: every dispatch passes `ResolveDispatchTargets`
  and the claim re-check.

## 5. Ledger

`asset_coverage` (tenant, asset, capability, vantage) → state (`due`,
`queued`, `covered`, `failed`, `blocked`, `paused`, `not_applicable`),
reason code, priority, next due, last attempt, last success, last outcome,
last tool, last run, failure streak, change token. Composite tenant foreign
keys; a partial index on due rows per tenant. It replaces
`scan_coverage_state` and `easm_dns_check_state` (whose rows become
`dns.dangling` / `dns.email` rows). `asset_attribute_freshness` stays: it
records facts observed, the ledger records work done.

Measured at 1 M assets × 4 capabilities (4 M rows): 638 MB heap, 379 MB
indexes; a due sweep of 5 000 rows takes 38 ms, a fair sweep of 50 rows for
each of 1 000 tenants 12 ms, one asset's explanation 0.05 ms.

## 6. Safety

- Scope stays the only authority; refused pairs become `blocked` with the
  gate's reason, visible and not counted as gaps.
- Budgets: discovery depth and per-root limits (RFC-088), a per-tenant
  per-capability daily budget, a per-tenant share of each planner tick.
- Kill switches: an exclusion stops an asset at once (claim re-check); the
  tenant setting turns automatic coverage off; a platform switch turns off
  one capability for every tenant.
- Every query is tenant-scoped; the explanation endpoint follows the asset's
  read permission and the caller's data scope.

## 7. Plan

| Step | Change | Status |
|---|---|---|
| P0-1 | HTTP probe results create web origin assets | #2127 |
| P0-2 | Seed targets of a stage plan name their asset | #2128 |
| P0-3 | Coverage policy in the registry and this RFC | #2129 |
| P0-4 | `asset_coverage` ledger; replaces two half-ledgers | #2130 |
| P0-5a | The ledger follows the policy (reconcile loop, preconditions) and the explanation endpoint `GET /assets/{id}/coverage` | #2132 |
| P0-5b | Planner: due pairs through the scope gate into one coverage run per capability, settlement from runs, daily budget, Strict off | #2134 |
| P0-5c | Gap detection: gaps, output drops, repeated failures to administrators and integrations; operator aggregates | #2135 |
| P0-5 | Due marking at ingest, planner, gap detectors, explanation endpoint | planned |
| P0-6 | Tenant setting for automatic coverage (default on; Strict off), audited | PR |
| P0-7 | Managed scans: coverage and enrichment scans are identified by `(managed_by, managed_key)`, never by name ([managed scans](../architecture/managed-scans.md)) | PR |
| P1 | Tenant and plan policy, priority, budgets, windows, outcome classes for throttling, coverage KPI | designed |
| P2 | Information-gathering sources, vantage rows, authenticated web coverage, targeted re-checks, ledger history | designed |
| P3 | Planner emits work-pool items; workflows plan from the ledger | designed |
