# RFC-068: Dynamic scan targets

| | |
|---|---|
| Status | Accepted (delegated, 2026-10-09; decisions T1–T8 adopted as recommended, §10). P0 in implementation |
| Scope | api (`pkg/domain/scan`, `internal/app/scan` target resolution, `internal/app/scanrun` step seeds, the inventory reader, `GET /assets?in_cidr=`, run dispatch report, metrics, one migration), web (New Scan targets and options, scan detail, run detail) |
| Architecture | [scan-targets.md](../architecture/scan-targets.md) |
| Related | RFC-030 (work distribution), RFC-046 (Scan → Run → Task, stage catalogue), RFC-054 (scope model: `*.x` covers `x`, tiers, proof, auto-join), RFC-065 (programs, run scope snapshot), RFC-067 (scan window policies), [scan-stages.md](../architecture/scan-stages.md), [active-probe-gate.md](../architecture/active-probe-gate.md) |

## 1. Summary

A scan of `*.example.com` must scan every subdomain the organization already
has **and** the ones found later. The same holds for an address range. This
RFC makes a wildcard domain and a CIDR **selectors**: the scan stores what the
user wrote, and every run expands it from the inventory as it is when the run
starts. Discovery stages inside a run keep adding names through the existing
hop router. Every target a selector adds is decided by the one dispatch gate,
exactly like an asset-group member: a selector authorizes nothing.

## 2. Problem

| Today | Effect |
|---|---|
| A wildcard is refused for any tool but subdomain discovery (`WILDCARD_TARGET`), and discovery gets the apex only | A weekly vulnerability scan of `*.example.com` cannot be saved |
| The web's "Host and its subdomains" copies up to 500 inventory names into the scan when it is saved | The list is frozen: a name found by certificate transparency on Tuesday is never scanned by Sunday's run; a removed name keeps being scanned until it is archived |
| A CIDR target always hands the whole range to the scanner | "Scan the hosts we know in 203.0.113.0/24" is not expressible; a /16 sweep is the only choice |
| Over-cap and hop-limit skips of chained stages are a log line | A runaway in-run expansion is invisible |

## 3. Goals and non-goals

Goals:

- `*.example.com` = the apex and every name the inventory holds at or under
  it, **re-read at every run**; names discovered during the run by earlier
  stages are added as today.
- A CIDR is swept (default, as today) or replaced by the inventory's
  addresses inside it (`inventory` mode).
- Freshness: skip assets not seen for N days; stale and inactive assets out
  unless asked; archived and deleted assets never.
- Caps per selector and per run, recorded on the run, counted in metrics.
- What each selector added is recorded on the run and shown on the run page;
  New Scan previews the live count; scheduled scans say targets are
  re-resolved at each run.
- Scope safety unchanged: every resolved target passes the dispatch gate; a
  selector never grants scope; another tenant's inventory never contributes.

Non-goals (P0):

- Tag and scope-entry selectors (§9, P1).
- Polling the inventory during a run for names found by other sources
  (certificate transparency, another scan): the next run takes them.
- A "resolving only" filter: the inventory has no DNS resolution state that
  is cleared when a name stops resolving, so the filter would lie (§9).
- Rule-based asset groups: groups stay a curated list read at each run.
- Plan limits per run (§9, needs the owner's numbers).

## 4. Model

### 4.1 Selectors live in `scans.targets`

The scan keeps one target list. Two forms in it are selectors:

| Form | Meaning at run start |
|---|---|
| `*.example.com` | the apex `example.com` (a typed target) + every **domain-class** asset (`domain`, `subdomain`) of the tenant named `example.com` or ending in `.example.com` |
| `203.0.113.0/24` with `cidr_mode = inventory` | every `ip_address` (or address-named `host`) asset of the tenant inside the range; the range itself is not dispatched |
| `203.0.113.0/24` with `cidr_mode = sweep` (default) | the range, handed to the scanner whole (unchanged) |

Everything else is a literal target. A wildcard root must be a domain the
platform lets anyone cover: a public suffix (`*.com`, `*.co.uk`), a shared
provider apex (`*.amazonaws.com`) or a denied name (`*.gov.vn`) is refused
when the scan is saved (`WILDCARD_TARGET`), with the scope guardrails'
rules (RFC-054 §8).

### 4.2 Options

`scans.target_options` (jsonb, default `{}`):

| Field | Values | Default |
|---|---|---|
| `cidr_mode` | `sweep`, `inventory` | `sweep` |
| `seen_within_days` | 0–365 (0 = any) | 0 |
| `include_stale` | take assets the lifecycle marked stale or inactive | false |

Options apply to what selectors add, never to a literal target. They are set
on create and edit, exported and imported with the scan, and copied by clone.

### 4.3 Caps

- **Per selector:** 5 000 assets (`MaxSelectorTargets`, the stage
  catalogue's per-parent cap past which a domain is a suspected wildcard DNS
  zone). The read is ordered by `last_seen` descending, so a capped selector
  keeps the names seen most recently. The run records `capped` and a warning.
- **Per run:** 10 000 targets after the gate, 1 000 jobs for a one-target
  scanner (unchanged). More than 20 000 candidates before the gate refuse the
  run, as for asset groups.
- **In run (unchanged):** stage `max_fanout` and per-parent caps, hop limit 3.

## 5. Resolution

### 5.1 At run start

`resolveScanTargets` (the one place a run's targets are built) expands the
selectors before the gate:

1. Literal targets, swept CIDRs and wildcard apexes are added by name.
2. Each selector reads the inventory (`ScanSelectorRepository`, one query
   pinned to the scan's tenant, `deleted_at IS NULL`, status filter, optional
   `last_seen` window, `LIMIT cap + 1`).
3. Each asset is added **by asset id** with its exclusion values (addresses,
   repository URLs), exactly like an asset-group member, and through the
   scanner type gate.
4. `ResolveDispatchTargets` decides every target: target validator, scope
   exclusions (fail closed), ownership (`easm.ActiveGate`: rejected,
   needs review, candidate, dependency, out of scope, proof), act scope of
   whoever runs the scan (by asset id: a restricted member's run skips
   assets outside their data scope), the private-range rule, the tier
   ceiling. Refusals are counted, as for groups.

The run then continues as today: program rules, zone routing, sensor
routing, the scope snapshot (RFC-065 §9), commands. Claim-time scope
re-check, scan windows (RFC-067) and the job signer ledger apply to these
targets exactly as to typed ones.

**Fail closed:** a selector whose inventory read fails or is not wired
refuses the run (`TARGET_SELECTOR_UNAVAILABLE`); it is never narrowed to the
apex in silence.

### 5.2 Subdomain discovery

A tool that implements `discover.subdomains` (subfinder) enumerates from a
root. It gets the apex only:

- a single-scanner scan of subfinder: the selector becomes its apex before
  resolution (unchanged behaviour); the inventory is not read;
- a workflow step of that stage: the run's seeds minus the names under a
  wildcard apex (`DiscoverySeeds`). The run context carries the apexes
  (`selector_roots`, never sent to a sensor).

### 5.3 During the run

Unchanged: the hop router (scan-stages.md §3) feeds what discovery stages
produced to later stages through the inventory, with the gate at every hop
(passive stages: only rejected names refused; active stages: `ActiveGate`;
intrusive stages: never fed), hop ≤ 3, fan-out caps, exactly-once plans and
per-target provenance (`scan_run_targets`: seed or derived, parent, relation,
hop, rule or skip reason). Seeds a selector added are deduplicated against
derived names. New: `scan_stage_targets_skipped_total{reason}` counts
`over_cap` and `hop_limit` skips.

### 5.4 Between runs

Nothing is stored on the scan. A scheduled run re-reads the inventory, so
names found by any source since the last run (certificate transparency,
another scan's discovery, an import, a connector) are scanned, and names
archived since are not.

## 6. Record and audit

| Where | What |
|---|---|
| `run.context.target_expansion` | per selector: `selector`, `kind` (`wildcard`, `cidr`), `matched`, `capped`, `sample` (≤ 10 names, freshest first) |
| `run.context.dispatch_warnings` | a line per capped selector |
| `run.context.targets` (workflows) / command payloads (single scans) | the resolved list (unchanged) |
| `scan_run_scope_snapshots` | the scope entries that covered the run's targets, hashed (unchanged) |
| `scan_run_targets` | in-run provenance (unchanged) |
| `GET /scan-runs/{id}` | `dispatch.target_expansion` |
| metrics | `scan_target_selector_expansions_total{kind,outcome}` (`expanded`, `empty`, `capped`), `scan_stage_targets_skipped_total{reason}` |

`target_expansion` and `selector_roots` are platform bookkeeping:
`StepRunContext` removes them from what a sensor receives.

## 7. API

- `POST /scans`, `PUT /scans/{id}`: `target_options` (object, optional; on
  update omitted = unchanged). Validation: `400` on an unknown `cidr_mode` or
  a window outside 0–365.
- `GET /scans/{id}`: `target_options`.
- `GET /assets?in_cidr=203.0.113.0/24[,…]` (at most 10 ranges): the address
  assets inside the ranges. Tenant and data scope as every list filter.
  Used by the New Scan preview next to `under=` (#1558).
- `GET /scan-runs/{id}`: `dispatch.target_expansion`.

No new route and no new permission.

## 8. Web

- **Targets step.** "Host and its subdomains" keeps `*.example.com` in the
  scan (dynamic) instead of copying inventory names. A live preview per
  selector: how many names the inventory holds now, the name seen most
  recently, a sample, and "re-resolved at each run; discovery steps add what
  they find". A CIDR offers *Sweep the whole range* or *Only known hosts*,
  with the known count. The wildcard hint no longer asks to replace the
  pattern for an active scanner.
- **Options step.** Freshness: "only assets seen in the last N days",
  "include stale assets".
- **Scan detail.** Dynamic targets are marked; a scheduled scan says
  "targets are re-resolved at each run".
- **Run detail.** "Resolved at start": per selector, matched, capped, sample;
  the stage lanes (unchanged) show what discovery added mid-run and why.

## 9. Later (P1, each on a real request)

| Item | Shape |
|---|---|
| Tag selector | `tag:prod` in targets: assets carrying the label, same reader and gate |
| Scope-entry selector | `scope:<entry id>`: a domain entry expands like its wildcard, a CIDR entry like inventory mode; follows the entry's edits |
| Plan limit | `scan_targets_per_run` plan key (owner sets Free/Pro numbers); refusal before dispatch |
| Notification | `scan.targets_capped` event to the scan's owner when a selector or a stage hits its cap |
| Resolving only | once DNS checks record and clear resolution state per name |
| Inventory-mode CIDR above /16 | the validator's sweep cap does not bound an inventory read; lift it for inventory mode, bounded by the per-selector cap |
| Migrate frozen expansions | offer "replace these N names with `*.x`" when a scan's targets are all under one root |

## 10. Decisions

Delegated to the implementer 2026-10-09 (owner rule: adopt recommendations).

| # | Question | Decision |
|---|---|---|
| T1 | Where selectors live | In `scans.targets`, as the user wrote them; options in `scans.target_options`. No second target list |
| T2 | When they resolve | At every run start, never at save |
| T3 | Wildcard expansion | Apex + domain-class assets at or under the root |
| T4 | CIDR default | `sweep` (unchanged); `inventory` opt-in |
| T5 | Default freshness | Active assets only; archived never; no day window |
| T6 | Caps | 5 000 per selector (freshest kept), run caps unchanged |
| T7 | Subdomain discovery | Apex only, at run start and as a workflow seed |
| T8 | Failure | Inventory read failure refuses the run |

## 11. Security

**Threat model.**

| Threat | Control |
|---|---|
| A selector used to scan what the tenant has not authorized | Expanded targets go through `ResolveDispatchTargets` by asset id: exclusions, ownership/attribution, scope entries (S1–S6), proof for platform sensors, tier ceiling, private-range rule; then the claim-time re-check, windows and the signer ledger. A test refuses a needs-review name, a rejected name, an excluded name and an address the CIDR holds but no scope entry covers |
| Cross-tenant read | The reader's query is pinned to the scan's tenant (`WHERE tenant_id = $1`); DB test with a second tenant's names and addresses under the same root and range |
| A restricted member widening their reach through a selector | Act scope by asset id: assets outside the actor's data scope are refused; free-text wildcards are refused for restricted members as any free text is |
| Runaway expansion (wildcard DNS, huge range) | 5 000 per selector, 20 000 candidates before the gate, 10 000 per run, 1 000 jobs; in-run caps and hop limit; metrics on both |
| A pattern reaching a sensor | A wildcard is never dispatched: apex + names, or refused (`WILDCARD_TARGET` for a pattern in another tool's `scanner_config.targets`) |
| SQL injection through the root | Bound parameters; LIKE wildcards escaped; a root containing `*`, `%`, `_`, `\` or a space is refused; a range is parsed (`netip`) and re-serialized |
| Silent narrowing | A failed or unwired reader refuses the run |
| Bookkeeping leaking to sensors | `target_expansion` and `selector_roots` are removed from the command context |

**Authorization impact.** No new route or permission. `in_cidr` narrows
`GET /assets` (`assets:read`, data scope applied). `target_options` rides on
`scans:write`.

## 12. Rollout

One migration (`001640_scan_target_options`): a jsonb column with a constant
default (no table rewrite) and an object check added `NOT VALID` then
validated. Existing scans keep their behaviour: CIDRs are swept, and a stored
`*.x` that used to be refused for an active scanner now runs as a selector.
Scans whose targets were frozen by the old web expansion keep their list.
