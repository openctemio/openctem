# RFC-153: Exploration

| | |
|---|---|
| Status | Partially implemented (2026-11-08): "how we found this" (P0); leads opened by rules and people, scored and dispatched through the coverage run path, approvals by tier, precomputed figures, the Exploration page (P1). AI proposals, campaigns and chain verdicts are designed, not built |
| Scope | api (`pkg/domain/exploration`, `internal/app/exploration`, `configs/lead-types.yaml`, `cmd/gen-lead-types`, migrations `exploration_layer`, `exploration_rollups`), web (finding and asset detail, the Exploration page, exposure chains and attack paths) |
| Architecture | [exploration.md](../architecture/exploration.md) |
| Related | RFC-093 (asset coverage ledger), RFC-122 (ingest receipts), RFC-132 (AI agents), RFC-054 (scope), RFC-148 (asset neighbourhood) |

## 1. Problem

OpenCTEM stores the facts of discovery well: assets and their relationships,
discovery lineage, coverage outcomes per asset and capability (including
"looked, nothing there"), runs, receipts and sightings. It does not connect
them into reasons. Nobody can ask "how was this found", "why did this scan
run", "what is the next question for this asset" or "is this path proven"
and get one answer.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | A thin exploration layer: **leads** (an open question with a typed next action, justified by existing records), typed **links** (an observation to the step it triggered and to what that step yielded) and append-only **verdicts**. It references existing records and never copies them. |
| D2 | Leads are opened by deterministic rules and by people first; AI agents may propose leads later, never dispatch or approve them. |
| D3 | One continuous exploration per organization; pentest campaign explorations and ad hoc investigations come later. |
| D4 | Approval tiers: passive steps run when the lead opens; active non-intrusive steps follow the organization's automatic coverage policy; intrusive steps always need a person with step-up. |
| D5 | Scoring, caps and stop rules are code, never a model's choice. |
| D5a | A 20 % share of each pass's dispatch slots goes to kinds of step the organization never tried; a kind of step whose last ten outcomes were all useless is demoted. |
| D6 | Proof wording: `proven` only from a deterministic check or a person with evidence. Exposure chains and attack paths are labelled "possible path, not proven" until a verdict exists. |
| D7 | An out-of-band interaction collector for blind proofs is a platform-owned sensor role, built only after its own threat model. |
| D8 | Learning priors: per organization in P1; aggregated counts across organizations (no identifiers, opt-out) may come later, never on self-managed installs unless enabled. |
| D9 | The read path and the propose contract are in Community; Enterprise builds estate analytics on the public extension points. |
| D10 | Clean-room implementation: our own design and code only. |
| D11 | Names: the feature is "Exploration", the unit a "lead"; UI rows "Next steps" and "How we found this". |
| D12 | Nothing is purged: leads, links and verdicts are kept. |

Routine scanning stays in the coverage ledger (RFC-093): a lead exists only
for work the ledger cannot express.

## 3. Phases

| Phase | Content | State |
|---|---|---|
| P0 | "How we found this" for findings and assets from stored data; the strip on the finding and asset pages; "possible path, not proven" labels | Built |
| P1 | Leads opened by rules and people, scored in code, dispatched through the coverage run path and the dispatch gate (fail closed), approvals by tier, precomputed figures, the Exploration page and the asset "Next steps" card | Built (2026-11-08) |
| P2 | Proposals by AI agents, rule suggestions from repeated outcomes, pentest campaign explorations, chain verdicts | Designed |

## 4. P0: the story (built)

`GET /api/v1/findings/{id}/story` and `GET /api/v1/assets/{id}/story` return a
short ordered chain (scope entry, discovery chain, scans, reporting sources,
finding), at most 16 steps, composed at read time. The permission is the one
of reading the subject; a step outside the caller's data scope or permissions
is hidden and counted, never named. Details and the security model:
[exploration.md](../architecture/exploration.md).

## 5. P1: leads from rules (built)

Details, tables, routes and tests: [exploration.md](../architecture/exploration.md).

- **Storage.** `explorations`, `exploration_leads`, `exploration_links`,
  `exploration_verdicts` (append-only by trigger), `exploration_rollups`.
  Every reference is a typed column with a composite `(tenant_id, id)`
  foreign key; one live lead per question (dedup key); nothing is purged.
- **Lead type catalog.** `configs/lead-types.yaml`, generated into Go and
  TypeScript. Each type maps to typed next actions (a stage catalog
  capability per subject asset type, with its allowed params) and a settle
  mode; the tier is always the stage catalog's.
- **Rules.** `dns.takeover_check`, `version.confirm`,
  `asset.gone_with_findings`, from states the platform derives itself (its
  DNS check, version matcher and liveness ledger). Rules re-read state each
  pass, so a failed pass loses nothing and nothing opens twice.
- **Scoring and dispatch.** Expected value in code (likelihood updated by
  the organization's outcomes x subject value / learned tool duration),
  caps (4 running, one per subject and capability, 5 live per asset, 500
  per exploration), the coverage daily budget, and dispatch only through
  the coverage run path (`StartCoverage`): the dispatch gate, signed jobs
  and the sensor's policy apply and the target is the subject's own name.
  A single admission point for every scan starter is not built yet; when it
  is, the controller moves behind it.
- **Approvals by tier.** Passive runs at once; active follows the
  organization's automatic coverage or a person with `scans:approve` and
  step-up; intrusive is never started by the system. Every state change and
  approval is audited.
- **Settlement.** Deterministic verdicts from the run: a finding reported,
  the liveness ledger after the step, or the cited version-match findings;
  "nothing found" is a recorded result.

## 6. Open decisions

- How an approved intrusive step runs: as a run attributed to the approver
  (with their act scope) or not at all. Today the controller blocks it.
- Four-eyes approval for intrusive steps as an organization policy.
- Whether exploration figures join the dashboard metric catalog as a widget
  (the rollup is ready for it).
- Lead ends for relationships, commands and evidence items need a unique
  `(tenant_id, id)` index on those large tables first.

## 7. Security (all phases)

- Tenant from the principal only; every query and every join tenant-bound.
- Every read through the data scope; hidden nodes keep no identifying field.
- A lead never carries scope: dispatch always passes the dispatch gate, the
  signed job and the sensor's local policy.
- Leads are opened only from reports bound to a command; unsolicited or
  quarantined reports never open one.
- AI principals have no approve permission; verdicts are append-only and
  audited.
