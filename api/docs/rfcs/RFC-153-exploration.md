# RFC-153: Exploration

| | |
|---|---|
| Status | Partially implemented (2026-11-07): "how we found this" for findings and assets (read only, no new tables); leads, links and verdicts are designed, not built |
| Scope | api (`pkg/domain/exploration`, `internal/app/exploration`, story reads), web (finding and asset detail, exposure chains and attack paths) |
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
| D4 | Approval tiers: passive steps run when the lead opens; active non-intrusive steps follow the organization's automatic coverage policy; intrusive steps always need a person with step-up. |
| D5 | Scoring, caps and stop rules are code, never a model's choice. |
| D6 | Proof wording: `proven` only from a deterministic check or a person with evidence. Exposure chains and attack paths are labelled "possible path, not proven" until a verdict exists. |
| D9 | The read path and the propose contract are in Community; Enterprise builds estate analytics on the public extension points. |
| D11 | Names: the feature is "Exploration", the unit a "lead"; UI rows "Next steps" and "How we found this". |
| D12 | Nothing is purged: leads, links and verdicts are kept. |

Routine scanning stays in the coverage ledger (RFC-093): a lead exists only
for work the ledger cannot express.

## 3. Phases

| Phase | Content | State |
|---|---|---|
| P0 | "How we found this" for findings and assets from stored data; the strip on the finding and asset pages; "possible path, not proven" labels | API built; web in progress |
| P1 | Leads opened by rules, scored, dispatched through the one admission point and the dispatch gate (fail closed), approvals by tier | Designed |
| P2 | Proposals by AI agents, rule suggestions from repeated outcomes, pentest campaign explorations, chain verdicts | Designed |

## 4. P0: the story (built)

`GET /api/v1/findings/{id}/story` and `GET /api/v1/assets/{id}/story` return a
short ordered chain (scope entry, discovery chain, scans, reporting sources,
finding), at most 16 steps, composed at read time. The permission is the one
of reading the subject; a step outside the caller's data scope or permissions
is hidden and counted, never named. Details and the security model:
[exploration.md](../architecture/exploration.md).

## 5. Security (all phases)

- Tenant from the principal only; every query and every join tenant-bound.
- Every read through the data scope; hidden nodes keep no identifying field.
- A lead never carries scope: dispatch always passes the dispatch gate, the
  signed job and the sensor's local policy.
- Leads are opened only from reports bound to a command; unsolicited or
  quarantined reports never open one.
- AI principals have no approve permission; verdicts are append-only and
  audited.
