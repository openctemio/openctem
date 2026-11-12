# RFC-110: Tenant lifecycles (sub-statuses and lifecycle schemes for findings)

| | |
|---|---|
| Status | Accepted (2026-10-16). Being implemented in small PRs; §11 lists what has shipped |
| Scope | api (catalog, schemes, engine layer, API), web (Settings → Findings → Lifecycle, finding drawer and list) |
| Related | the finding status lifecycle and its transition engine (`docs/architecture/finding-status-lifecycle.md`), RFC-064 (modules, entitlements, plans), RFC-097 (ticket field and status mapping), RFC-098 (remediation tasks), step-up re-authentication (`docs/architecture/step-up-reauth.md`) |

## 1. Summary

Organizations want their own words and their own rules for how a finding moves: "In development",
"In review", "Waiting for vendor", "Bounty paid"; "a P0 finding is claimed fixed only with a pull request
link"; "only the security champions may move a finding to Ready for retest". They must get that without
weakening a single platform rule and without changing what a metric means.

**Decision: an additive layer on top of the canonical lifecycle, never a replacement.**

1. **The canonical statuses stay the platform invariant.** `findings.status` keeps its eight values (new,
   confirmed, in_progress, fix_applied, resolved, false_positive, accepted, duplicate), the closure reason
   and the verification method. Every metric, the SLA, the CI gate, VEX / CSAF / CycloneDX exports,
   ticket categories and every security rule read only these.
2. **Sub-statuses** are an organization's labels, each bound for ever to one canonical status (and, under a
   closed status, to one closure reason). A finding carries at most one, in `findings.sub_status_id`, and
   the database guarantees the two never disagree (a composite foreign key on
   `(tenant_id, sub_status_id, status)`).
3. **Lifecycle schemes** say which moves between sub-statuses exist and which extra constraints they carry:
   required fields, a longer note, a required permission, actor kinds that may not make the move, extra
   approval. A scheme can only **add** constraints. It is versioned: draft, validate, simulate, publish
   (with step-up re-authentication), roll back by publishing an older version again.
4. **Per-context schemes.** An organization may publish more than one scheme, each with a context
   selector (finding source, finding type, severity, priority, KEV, tool). The first scheme whose selector
   matches a finding applies; a scheme without a selector is the default.
5. **The platform decides first.** The transition engine decides the canonical move exactly as it does
   today (permissions, four-eyes approval for false positives and accepted risks, the evidence matrix for
   resolves, the fix-claim rules, the pentest module, the delegated-actor limits). The tenant layer then
   runs on that decision and can only add requirements or blocks, or turn a direct move into a request. A
   property test proves, over random schemes, that a move the tenant layer allows is always a move the
   platform allows.

The feature is called **Lifecycles** (Settings → Findings → Lifecycle; API `/lifecycles`), because
"workflows" is the trigger-and-action automation module.

## 2. Invariants a scheme can never relax

| Invariant | Where it is enforced |
|---|---|
| Only edges of the canonical lifecycle (`ValidStatusTransitions`) or same-status moves | engine stage 2; the scheme compiler refuses other edges |
| `findings:status`, `findings:verify`, `findings:fix_apply`, `findings:triage`, `findings:write` as today | engine stage 3 |
| False positive and accepted risk are requests a second person approves (four-eyes) | engine stage 3; a tenant guard cannot turn a request into a direct move |
| Resolve evidence by risk (retest or second verifier for critical / P0 / KEV, checklist for high / P1) | engine stage 3 |
| A fix claim is a person's, on their own finding, with a note | engine stage 3 |
| Acceptance always ends, capped by priority | approval service, unchanged |
| Pentest findings belong to the pentest module | engine stage 2 |
| A ticket webhook only reports work state | engine stage 3 |
| Platform evidence moves (covered scan, retest, VEX statement, regression reopen, acceptance expiry) | never evaluate tenant guards; they land on the default sub-status of the new status |
| Metrics, SLA, CI gate and exports read canonical status and closure reason only | a lint test fails when a metric query reads `sub_status_id` |

## 3. Data model

```
lifecycle_sub_statuses   (tenant_id, id, object_kind, canonical_status, closure_reason, key, name, labels,
                          description, color, sort_order, archived_at, created/updated at/by)
                          UNIQUE (tenant_id, object_kind, key); UNIQUE (tenant_id, id, canonical_status)
lifecycle_schemes        (tenant_id, id, object_kind, key, name, description, priority, context,
                          published_version_id, archived_at, created/updated at/by)
lifecycle_scheme_versions(tenant_id, id, scheme_id, version, state draft|published|superseded, spec,
                          spec_hash, note, created at/by, published at/by)
findings.sub_status_id   FK (tenant_id, sub_status_id, status)
                         -> lifecycle_sub_statuses (tenant_id, id, canonical_status)
```

- **Category is immutable.** A trigger refuses a change of a sub-status's canonical status or closure
  reason. A sub-status is never deleted, only archived (and only when no published version uses it).
- **Every platform writer keeps working unchanged.** A `BEFORE INSERT OR UPDATE` trigger on findings drops
  the sub-status to NULL (the scheme's default for that status) whenever the status changes and the writer
  did not pick a sub-status of the new status, and whenever the closure reason no longer matches the
  sub-status it is bound to. The composite foreign key therefore never fails for the about thirty
  platform bulk writers that move statuses.
- **Versions are immutable once published.** A trigger refuses an update of a published or superseded
  version's spec. There is at most one draft per scheme (a partial unique index).
- **System lifecycle and templates are code**, not rows: the system lifecycle is the canonical map with no
  tenant guards; templates are read-only specs copied into a tenant draft. No row has a NULL tenant.
- **Live impact:** the new column is NULL on every existing row; the foreign key is added `NOT VALID` and
  validated in a separate migration (instant: every value is NULL); the index is built concurrently.

## 4. Scheme spec

```jsonc
{
  "sub_statuses": ["<sub-status id>", "..."],          // the catalog entries this scheme uses
  "defaults": { "in_progress": "<id>" },               // per canonical status; else the canonical label
  "person_moves": "canonical_plus_listed",             // or "listed_only"
  "transitions": [
    {
      "id": "claim_with_pr", "name": "Mark fixed (pull request)",
      "from": ["<id>", "status:in_progress"],          // sub-statuses or a whole canonical status
      "to": "<id>",                                     // a sub-status, or "status:<canonical>"
      "when": [ { "field": "priority_class", "op": "in", "value": ["P0", "P1"] } ],
      "guards": [
        { "kind": "require_note", "min_len": 20 },
        { "kind": "require_fields", "fields": ["fix_reference"] },
        { "kind": "require_permission", "any_of": ["findings:verify"] },
        { "kind": "deny_actor_kinds", "kinds": ["workflow", "ticket_inbound", "api_key"] },
        { "kind": "require_approval" }
      ]
    }
  ]
}
```

- **`person_moves`:** `canonical_plus_listed` (default) keeps every canonical move available (landing on
  the target's default sub-status) and adds the listed ones; `listed_only` offers only the listed moves, so
  a regulated organization can force a path. The validator then checks that every open sub-status can
  still reach every closed canonical status.
- **`when`** decides whether the guards apply (all conditions must match). Fields come from a closed,
  typed catalog: `severity`, `priority_class`, `is_kev`, `source`, `finding_type`, `tool_name`. Operators:
  `eq`, `neq`, `in`, `not_in`, `gte`, `lte` (ordered fields only), `exists`. No regular expressions, no
  expressions, no functions, no network.
- **Guards** only add constraints:

| Guard | Effect |
|---|---|
| `require_note {min_len}` | a note of at least `min_len` characters (1–500) |
| `require_fields {fields}` | inputs from a closed catalog: `ticket_link`, `fix_reference`, `change_id`, `target_version`, `due_date`, `compensating_control` |
| `require_permission {any_of}` | the actor holds one of these finding permissions (on top of the platform's) |
| `deny_actor_kinds {kinds}` | the move is refused for these delegated actors: `workflow`, `ticket_inbound`, `api_key` |
| `require_approval` | the move becomes a request a second person approves (a request stays a request) |

- **Limits:** 30 sub-statuses per kind, 10 schemes per kind, 60 transitions per scheme, 8 guards per
  transition, 8 conditions per `when`, 50 values per list, 64 KiB per spec. Names are plain text of at most
  64 characters; descriptions at most 500; colours come from a fixed token palette.

## 5. Evaluation

```
platform := vulnerability.EvaluateTransition(facts, actor, to.status)   // unchanged
decision := lifecycle.Apply(compiled, platform, facts, actor, from, to) // can only narrow
```

Order: tenant and data scope → canonical edge → platform invariants → tenant layer. The tenant layer:

1. finds the scheme's transitions for `(from place, to)`. A move onto a specific sub-status always needs a
   listed transition; under `canonical_plus_listed` a canonical move to the target's default label (and a
   reset to the current status's default label) stays available unlisted; under `listed_only` every move
   must be listed. Otherwise the move is blocked (`not_in_lifecycle`);
2. evaluates the transition's `when`; when it matches, every guard adds its requirement or block;
3. never clears a block, never removes a requirement, and changes the mode only from `direct` to
   `request`.

Same-status moves (a label change between two sub-statuses of one canonical status) need `findings:status`
and, under a closed status, a sub-status bound to the same closure reason (a change of closure reason is a
decision, not a label). The engine is pure (no IO, no clock); the caller loads the facts and the compiled
scheme. Compiled schemes are cached per published version id, so a new publish needs no invalidation.

**Who is evaluated against the tenant layer:** people, organization API keys, automation workflows and
ticket webhooks (as their principal). **Who is not:** platform evidence moves (§2), and a lifecycle
migration on publish (which only remaps between sub-statuses of the same canonical status).

## 6. API

| Route | Gate | Notes |
|---|---|---|
| `GET /api/v1/lifecycle-sub-statuses` | `findings:read` | catalog, archived ones on request |
| `POST /api/v1/lifecycle-sub-statuses`, `PATCH .../{id}`, `DELETE .../{id}` (archive), `POST .../{id}/reactivate` | `findings:lifecycles:write` | plan limit on additions; category immutable |
| `GET /api/v1/lifecycles`, `GET /api/v1/lifecycles/{id}`, `GET .../{id}/versions[/{version}]` | `findings:read` | schemes with the published and draft versions |
| `POST /api/v1/lifecycles`, `PATCH .../{id}`, `DELETE .../{id}` (archive), `POST .../{id}/versions` (new draft), `PUT .../{id}/versions/{version_id}` (edit the draft, `If-Match: <spec_hash>`), `POST .../{id}/versions/{version_id}/test` (validate) | `findings:lifecycles:write` | |
| `POST /api/v1/lifecycles/{id}/versions/{version_id}/publish` | `findings:lifecycles:write` + step-up | a draft is put in force; an older version is published again as a new version copied from it (roll back); audited |
| `GET /api/v1/findings/{id}/transitions`, `POST /api/v1/findings/transitions/preview` | `findings:read` | include sub-status moves and tenant reasons |
| `PATCH /api/v1/findings/{id}/status` | as today | accepts `sub_status_id` and `fields` |

The finding resource gains `sub_status` (`{id, key, name, color}` or null); lists filter by `sub_status`.

## 7. Limits

The catalog is capped by two organization limits (`lifecycle_sub_statuses` and `lifecycle_schemes`, see `docs/architecture/limits.md`). An organization is unlimited unless an operator or the hosted control plane sets them. A hosted offer typically sets:

| Tier | Sub-statuses | Schemes |
|---|---|---|
| Entry | up to 3 labels, no guards | none (the system lifecycle) |
| Mid | up to 30 | 1 per kind, with guards |
| Top | up to 30 | up to 10 per kind, with context selectors |

A limit caps what an organization may add: after a lowering the published schemes keep working.

## 8. Threat model

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | A custom move bypasses four-eyes or verification | the platform decides first; the tenant layer can only narrow | property test over random specs: tenant-allowed ⇒ platform-allowed, requirements ⊇, request stays request |
| T2 | A delegated actor escalates | delegated actors are evaluated as their principal against both layers; `deny_actor_kinds` | negatives per actor kind |
| T3 | Metric distortion ("Won't fix" under resolved) | closed sub-statuses bind a closure reason of their status; metrics read canonical only | metric lint |
| T4 | A guard blocks a regression reopen or an expiry | evidence moves never evaluate tenant guards | per-mover tests |
| T5 | Cross-tenant sub-status | composite foreign key on `(tenant_id, sub_status_id, status)`; every query tenant-scoped | cross-tenant negatives |
| T6 | Denial of service by spec | hard limits, closed catalogs, no regex; compiled once per version | compiler fuzz |
| T7 | A stolen admin session rewrites the lifecycle | publish needs step-up re-authentication and is audited | auth tests |
| T8 | Label exfiltration | VEX / CSAF / CycloneDX carry canonical values only; names are plain text, escaped | |
| T9 | Admin lockout (a guard nobody can satisfy) | the validator refuses unreachable statuses and dead ends with `listed_only` | validator tests |

## 9. UI

Settings → Findings → Lifecycle: a lane per canonical status group with its sub-statuses (add, rename,
reorder, archive), the schemes with their versions, a move matrix and a move editor ("When … then
require …"), a simulator ("as this role, on this finding"), and a publish dialog. The finding drawer and
list show the sub-status pill with its canonical status in grey, and the status menu lists sub-status moves
with what each needs. Every string goes through i18n (en and vi); organization labels are organization
data with optional per-language names.

## 10. Remediation tasks, ticket mapping, reports

- Remediation task sub-statuses (labels inside derived task states, hold reasons) follow once the task
  model is complete; `object_kind` already allows the extension.
- Ticket status mapping by sub-status, with a canonical fallback, builds on RFC-097 profiles.
- A flow report (time in sub-status, cumulative flow) reads the timeline rows.

## 11. Delivery

| Step | Content | State |
|---|---|---|
| 1 | Schema: catalog, schemes, versions, `findings.sub_status_id` with its foreign key and reset trigger; domain catalog types and repository | in review |
| 2 | Pure engine layer: spec compiler, validator, guards, scheme selection, property test, fuzz | in review |
| 3 | Catalog and schemes API (versions, validate, publish with step-up, roll back), permission `findings:lifecycles:write`, plan limits | in review |
| 4 | The tenant layer wired into every status path (sub-status changes only as engine-decided, audited moves); `PATCH /status` with `sub_status_id` and `fields`; the finding resource; the allowed moves and the dry run; the timeline | in review |
| 4b | Sub-statuses and fields on approval requests; the list filter by sub-status; simulate | designed |
| 5 | Settings → Findings → Finding lifecycle (sub-status lanes, draft editor, check, publish with step-up, version history and roll back) | in review |
| 6 | Drawer, list and bulk with sub-statuses (sub-status pill, status menu with sub-status moves and their requirements, bulk dry run) | in review |
| 7 | Templates, extra approval steps, ticket mapping by sub-status, flow report | designed |
