# Exploration: how we found this

Design: [RFC-153](../rfcs/RFC-153-exploration.md).

OpenCTEM keeps the facts of discovery in many places: the asset's discovery
lineage, the scope entries, the scan runs and their steps, the targets each
run planned, the ingest receipts and the finding sightings. A story puts the
ones that explain one finding or asset into a short ordered chain, read at
request time. Nothing is copied and no table is added: every step points at
the record it comes from.

## Simplest path

The finding page and the asset page show **How we found this**: a compact
timeline from the scope entry, through the assets the subject was discovered
under, to the scans and sources that reported it. Each step links to its
record. A step the viewer may not see shows as "1 step you cannot see".

Web: `web/src/features/exploration` (`StoryTimeline`, the one component for
every story; `FindingHowWeFoundThis` in the finding page's rail); the asset
page and sheet show it inside their discovery section
(`features/assets/components/asset-lineage-section.tsx`).

## API

| Route | Gate | Answers |
|---|---|---|
| `GET /api/v1/findings/{id}/story` | `findings:read` | the finding's story; not readable as the finding: 404 |
| `GET /api/v1/assets/{id}/story` | `assets:read` | the asset's story; outside the caller's data scope: 404 |

A story is `{subject, steps[], hidden, truncated, more_reports, first_seen_at,
last_seen_at, max_steps}`. Each step has a `kind`, `hidden`, an optional `at`
and one detail object:

| Kind | Detail | From |
|---|---|---|
| `scope_entry` | id, target type, pattern, the chain asset it matches, `excluded_by` (an exclusion in effect that also matches the subject) | the scope entry in effect covering the asset, else its closest visible ancestor (`scope.Explainer`) |
| `asset` | id, name, type, `via` (how it leads down: parent, contains, exposes, serves_certificate, resolves_to), discovery source and tool; `subject` on the asset of an asset story | discovery lineage ([easm.md](easm.md), "Discovery lineage"), at most 5 ancestors |
| `scan` | role (`discovered`, `scanned`, `reported`), run, scan, run status, step name, capability, tool, `relation` | `scan_runs`, `scan_run_steps`, `scans`; for an asset, `scan_run_targets` (the first run that derived it, the latest that planned it) |
| `report` | channel, tool, tool version, sensor, sender, receipt, first and last seen, seen count, backfilled | [finding sightings](finding-sightings.md) (first three reporters, first first; `more_reports` counts the rest); for an asset, the upload receipt that created it (`assets.import_id`) |
| `finding` | id, title | the finding |

Order: scope entry, ancestors from the root down, (asset story: the run that
derived the asset), the asset, then for a finding each reporting source
preceded by the run of its last report and the finding last; for an asset
the upload that created it and the latest run that scanned it.

## Security

- **Same permission as the subject.** The finding story reads the finding
  through `GetFindingWithScope`, the read of `GET /findings/{id}`: tenant,
  data scope, assignee visibility and pentest campaign membership. The asset
  story reads through `GetAssetInCallerScope`. The data scope guard on
  `/findings/{id}/**` and `/assets/{id}/**` answers 404 first.
- **Hidden, never leaked.** A step the caller may not see is returned as
  `{kind, hidden: true}` (an asset keeps its `via`) and counted in `hidden`:
  - an ancestor outside the caller's data scope (the lineage query returns no
    identifying column for it);
  - the finding's asset when the finding is readable but the asset is not (a
    finding assigned to the caller on an asset outside their scope): one
    hidden step, its chain is not walked and no scope entry is tested;
  - a scan run without `scans:read` (the run is not read at all).
  `Story.Seal` strips every hidden step again before it is returned.
- **Scope entries** are evaluated only with `attack_surface:scope:read`, and
  only against the subject and its visible ancestors: an entry matching a
  hidden ancestor would reveal its name. Without the permission no scope step
  is produced and none is counted.
- **Sensors** appear with `sensors:read` only, as in the sightings answer; a
  shared platform sensor is never one of the tenant's sensors.
- **Tenant isolation.** Every query is bound to the caller's tenant on every
  join; a step run joins only through its own tenant-bound run. Another
  tenant's id answers 404.

Tests: `internal/infra/http/routes/exploration_story_db_test.go` (chain,
hidden ancestor, assigned finding on an out-of-scope asset, no `scans:read`,
cross-tenant, gates), `internal/app/exploration/story_test.go`,
`pkg/domain/exploration/story_test.go`.

## Performance

A story is bounded: at most `max_steps` (16) steps, 5 ancestors, 3 reports,
8 runs read in one query, a 5 second budget for all its reads. Every read uses
an index (`TestStoryRepository_ReadsUseIndexes_DB` checks the plans on a
seeded table):

| Read | Index |
|---|---|
| lineage | `assets_pkey`, `idx_asset_rel_target` (bounded recursive walk, existing lineage read) |
| sightings | `ux_finding_sightings_source` |
| runs of the reports | `uq_scan_runs_tenant_id_id`, `scan_run_steps_pkey` |
| runs that derived or targeted an asset | `ix_scan_run_targets_asset` |
| upload that created an asset | `assets_pkey`, `ingest_receipts_pkey` |

## Key files

- `pkg/domain/exploration/story.go`: the story model, `Seal`, `PickReports`.
- `internal/app/exploration/story.go`: composition and redaction.
- `internal/infra/postgres/exploration_story_repository.go`: runs, asset runs, asset receipt.
- `internal/infra/http/handler/exploration_story_handler.go`, `internal/infra/http/routes/exploration.go`.
- `pkg/domain/exploration/lead.go`, `repository.go`: leads, links, verdicts.
- `configs/lead-types.yaml`, `cmd/gen-lead-types`, `pkg/domain/exploration/catalog.go`: the lead type catalog.
- `internal/app/exploration/rules.go`, `controller.go`; `pkg/domain/exploration/score.go`; `internal/infra/controller/exploration.go`.
- `internal/infra/postgres/exploration_lead_repository.go`; migration `exploration_layer`.

## Leads, links and verdicts: storage

A **lead** is an open question about one subject (an asset or a finding)
with a typed next action: one capability of the stage catalog plus
params, never a tool command line. Free text is only the rationale, which is
shown escaped and never executed. The tier comes from the stage catalog,
never from whoever opened the lead.

| Table | Holds |
|---|---|
| `explorations` | one objective with its budget; one `continuous` exploration per tenant (`uq_explorations_continuous`) |
| `exploration_leads` | the question: lead type, state, capability and params, `action_hash`, tier, subject, reason code, rationale, origin (`rule`, `user`, `ai_agent`, `system`) and its reference, likelihood band, score and its inputs, `dedup_key`, attempts, approval |
| `exploration_links` | typed links of a lead: `derived_from` (the evidence that justified it), `dispatched_as` (the run it started), `yields` (what that run produced, `not_found` included) |
| `exploration_verdicts` | append-only answers: `proven`, `refuted`, `inconclusive`, with the checker's tier (`deterministic`, `human`, `heuristic`, `ai`) and evidence references, never bodies |

Lead states: `proposed`, `awaiting_approval`, `open`, `running`, `blocked`
(live), then `done`, `refuted`, `exhausted`, `dismissed`, `superseded`
(closed, `closed_at` set). A closed lead never moves again
(`pkg/domain/exploration/lead.go`, `CanMove`), and `awaiting_approval` never
goes straight to `running`.

Invariants the database keeps:

- **Tenant isolation on every reference.** Each end of a link is a typed
  column (`asset_id`, `finding_id`, `scan_run_id`, `ref_lead_id`) with a
  composite foreign key on `(tenant_id, id)`; a lead's exploration and
  subject likewise. A row can only point at rows of its own tenant.
- **One live lead per question:** `uq_exploration_leads_live_dedup` on the
  dedup key (lead type, subject, capability) while the lead is live.
- **One link per lead, relation and end:** the same run is never recorded
  twice as a lead's dispatch.
- **Nothing is lost.** A removed asset, finding or run clears only that end
  column (`ON DELETE SET NULL (column)`); the link keeps its `end_kind`.
  Leads and links are kept forever.
- **Verdicts are append-only.** A trigger refuses UPDATE and DELETE; the one
  change a row takes is clearing `decided_by` when that account is deleted,
  and a verdict goes only with its lead. `proven` comes only from a
  deterministic check or from a person with evidence (`Verdict.Validate`).
- Row-level security policies in shadow mode, as on every tenant table.

Reads follow the reader's data scope: a restricted member sees a lead only
when its subject asset (or the subject finding's asset) is in scope; a member
with no scope row sees none. Asset merges move a lead's subject and its asset
links to the kept asset; finding merges move a lead's subject finding, while
a link to a finding stays on the tombstone as history.

Tests: `internal/infra/postgres/exploration_lead_repository_db_test.go`
(lifecycle, dedup, compare and set, cross-tenant references refused on every
end, data scope, append-only verdicts), `pkg/domain/exploration/lead_test.go`.

## Lead type catalog

`configs/lead-types.yaml` is the single source of truth for the kinds of
question a lead may ask. `make generate-lead-types` (`cmd/gen-lead-types`)
checks it and writes `pkg/domain/exploration/lead_types_generated.go` and
`web/src/features/exploration/lib/lead-types.generated.ts`; `-check` (and
`TestGeneratedFilesUpToDate`) fails when they are stale.

| Lead type | Asks | Action (tier from the stage catalog) |
|---|---|---|
| `dns.takeover_check` | can this dangling alias be claimed? | `check.takeover` (T1) on a domain or subdomain |
| `version.confirm` | is the version a critical match was made on really there? | `probe.http` (T1) |
| `asset.gone_with_findings` | is an asset reported gone really gone, while findings stay open on it? | `resolve.dns` (T0) for names, `probe.http` (T1) for web services and hosts, `discover.hosts` (T1) for addresses |

Each entry has a version (rules record `<id>@<version>` as a lead's origin),
a likelihood band (the score's prior), a value weight, a maximum number of
dispatches, its reason codes and how a finished step answers the question
(`settle`): `finding` (proven when the step reports a finding on the
subject), `liveness` (the liveness ledger after the step) or `match` (the
cited version-match findings after the step). An action names a capability, the subject
asset types it applies to, and the params it accepts. The generator refuses
an unknown capability, an asset type the capability does not take, and any
field it does not know (a tier cannot be written in the YAML: it is always
the stage catalog's). `CheckCatalog` refuses a lead whose type, reason,
action, params or tier the catalog does not declare.

## Rules

Rules are deterministic code (`internal/app/exploration/rules.go`) that
open leads in the tenant's continuous exploration. They re-read trigger
states on every pass instead of consuming events: a failed pass loses
nothing, and a repeated pass opens nothing twice (the live dedup key, and
every trigger leaves out subjects that have a live lead of the type or one
closed within 30 days, `exploration.ReaskAfter`).

| Rule (lead type) | Trigger (`internal/infra/postgres/exploration_trigger_repository.go`) | Reason code |
|---|---|---|
| `dns.takeover_check` | a domain or subdomain with an active `dangling_cname` exposure from the platform's DNS check (`source = 'easm_dns'`) and no open `subdomain_takeover` | `cname_dangling` |
| `version.confirm` | an open `version-match` finding (not since reported by a scanner) in KEV or critical, below the likely threshold (`vulnmatch.LikelyThreshold`) | `kev_on_unconfirmed_version` |
| `asset.gone_with_findings` | the liveness ledger holds the asset `gone` while findings stay open on it | `gone_with_open_findings` |

Each lead cites its evidence as `derived_from` links: the asset, and up to
five findings. The action is the catalog's action for the subject's type;
a subject no action applies to gets no lead.

- **Trusted inputs only.** Triggers read states the platform derives itself
  (its DNS check, its version matcher, its liveness ledger). An imported
  exposure or an unsolicited report never opens a lead.
- **Initial state by tier.** Passive (T0) leads open at once. Active (T1)
  leads open at once only while the organization's automatic coverage is on
  (`coverage.GovernanceSwitch`, the switch the coverage planner uses);
  otherwise, or when the switch cannot be read, they wait for approval.
  Intrusive (T2) leads always wait for a person.
- **Caps.** At most 5 live leads per asset and 500 per exploration; each
  rule reads at most 100 candidates per pass. Archived and soft-deleted
  assets are never subjects.
- **Audit.** Every opened lead is an `exploration.lead_opened` event with the
  rule as the actor (`rule:<type>@<version>`), the lead's state, capability,
  tier and action hash.

Tests: `internal/app/exploration/rules_test.go` (catalog action per type,
T1 waits when automatic coverage is off or unreadable, tenant-bound, caps,
audit), `internal/infra/postgres/exploration_trigger_repository_db_test.go`
(only the platform's DNS check counts, another tenant's triggers never show,
asked subjects are left out, version-match thresholds, gone with open
findings only).

## Scoring and dispatch

`ExplorationController` (`internal/infra/controller/exploration.go`, module
Scans, every 2 minutes, one replica at a time) runs
`internal/app/exploration/controller.go` for every tenant with assets:

1. the rules open leads;
2. blocked leads whose recheck time came reopen;
3. running leads settle from their run;
4. open leads are scored and the best are dispatched.

**Score** (`pkg/domain/exploration/score.go`, code only):

```
score = P(useful) x value / cost
P     = (prior x 4 + useful) / (4 + tried)       prior: low .1, medium .3, high .6
value = criticality (critical 4, high 3, medium 2, else 1) x public 2 x open KEV or critical finding 3
        x crown jewel 2 x the lead type's value weight
cost  = the tool's learned mean duration for the tenant (tool_duration_stats), 60 s when unknown
```

`tried` and `useful` are the tenant's settled verdicts of the same (lead
type, capability) cell (useful = proven). A cell whose last 10 outcomes were
all useless is demoted (score x 0.2). The inputs are stored with the lead
(`score_inputs`), so a person can see why it ranks where it does.

**Selection.** 20 % of each pass's slots (at least one) go first to leads of
cells the tenant never settled, so new kinds of step get tried; the rest go by
score. At most one lead per subject and capability is picked, and none whose
(subject, capability) is already running.

**Caps.** 4 running leads per tenant; one running per subject and capability;
every dispatch counts against the tenant's coverage daily budget
(`ASSET_COVERAGE_DAILY_BUDGET`): the ledger's attempts and the leads' own
dispatches of the last 24 hours share it.

**Dispatch** goes only through the coverage planner's run path,
`scan.Service.StartCoverage`, as the coverage policy's system authority:

- the dispatch gate (`ResolveDispatchTargets`, fail closed): scope entries,
  exclusions, guardrails, the active-scan ownership gate, zone routing;
- the signed job and the sensor's local policy;
- the target is always the subject asset's own stored name (the ledger's
  target form), never anything a lead carries;
- the subject's ledger pair, if the ledger holds one, is marked queued on the
  run, so the ledger settles it too.

Outcomes of a dispatch:

| Gate answer | Lead |
|---|---|
| run started | `running`, `dispatched_as` link, attempts + 1 |
| target refused (out of scope, excluded, guardrail...) | `blocked` with the gate's code, rechecked after 6 hours; nothing runs |
| the capability cannot run now (readiness) | `blocked` with the readiness reason, retried after 30 minutes |
| the capability's coverage run is still active | stays `open` (next pass) |

Before dispatch the lead is checked again: an intrusive (T2) step is blocked
(`intrusive_needs_person`) and never started by the system; an active (T1)
step that no person approved moves back to `awaiting_approval` when automatic
coverage is off (or unreadable); a subject removed or archived supersedes
the lead; a lead at its type's attempt limit is exhausted; a catalog action
that no longer applies to the subject's type blocks it.

**Settlement.** When the run finishes, the lead type's settle mode answers:

| Mode | Proven | Refuted | Otherwise |
|---|---|---|---|
| `finding` | the run reported a finding on the subject (`yields` links to it, `created` or `confirmed`) | the run completed without one (`yields` the subject, `not_found`) | |
| `liveness` | the liveness ledger, checked after the run, holds the subject gone, unreachable or unresolvable | it answered (alive) | not checked since the run: inconclusive |
| `match` | a cited version-match finding is now likely or was reported by a scanner | every cited finding closed | inconclusive |

A failed, cancelled, timed-out or blocked run, a run that stalls past 24
hours and an inconclusive answer are `inconclusive`: the lead waits 30
minutes (`blocked`, then reopened) and is dispatched again until the type's
attempt limit, then it is `exhausted`. Every verdict is `deterministic` with
the run (and the findings) as evidence references.

**Audit.** Every state change (`exploration.lead_state_changed`, with from,
to and reason) and every verdict (`exploration.lead_verdict`) is audited with
the controller as the actor and the lead's action hash.

Tests: `internal/app/exploration/controller_test.go` (the subject's own name
in the lead's tenant is the only target, a refused target never runs and is
rechecked, gate errors block, approval tiers at dispatch, the daily budget
and the running cap, busy capability, settlement by finding and liveness,
failed runs exhaust, archived subjects supersede, tenant-bound passes),
`pkg/domain/exploration/score_test.go`,
`internal/infra/postgres/exploration_controller_repository_db_test.go`.

## Not yet built

- Retest outcomes and evidence items as steps.
- Approvals by people, leads opened by people and the Exploration page:
  designed in RFC-153, not built.
