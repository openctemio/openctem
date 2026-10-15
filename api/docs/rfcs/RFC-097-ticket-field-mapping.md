# RFC-097: Ticket field and status mapping

| | |
|---|---|
| Status | Proposed (2026-10-15). Implemented: the mapping model (profiles per integration, project, issue type and object kind; versions with draft, publish and rollback), the attribute catalog with fixed inbound capabilities, the template language, validation against the tracker's create fields and workflow, drift detection, transition path planning, inbound intents and decisions, presets, auto-suggest, copy, import and export, outbound and inbound preview, the simulator, the API; the console (Settings → Integrations → Ticket field mapping: two-column field mapper with transforms and a sample render, workflow graph with outbound and inbound status maps and the simulator, previews, history with diff and rollback, import/export, dry run, drift check). Designed: the outbound and inbound engines that use published profiles when issues are created and changed, a nightly drift check |
| Scope | api, web |
| Related | RFC-006 (ticketing provider and mapping), RFC-006 phase 3 (bidirectional status sync), RFC-015 (remediation groups), RFC-040 (output encoding of sensor-controlled text) |

## 1. Summary

An organization decides which OpenCTEM attribute goes to which tracker field and which tracker field comes back
to which attribute, separately for **findings** and for **remediation tasks**, per destination project and issue
type. The same profile maps OpenCTEM states to the project's real workflow statuses and workflow statuses back to
**intents**. A tracker never closes a finding: Done means a fix was claimed, and "Won't Do" opens a
risk-acceptance request that a second person decides.

## 2. Model

```
integration (one tracker site)
  └─ profile (object kind × project × issue type)     unique per destination
       └─ versions                                   one open draft, one published, the rest superseded
            spec: minimization, field rows, status map, comment settings
            snapshot: the tracker metadata the version was checked against (drift baseline)
```

Tables `ticket_mapping_profiles` and `ticket_mapping_versions` (migration `ticket_mapping_profiles`), both
tenant-scoped. Publishing never rewrites a published row; a rollback copies an old spec into a new draft.

### 2.1 Field rows

| Key | Values |
|---|---|
| source | an attribute (`finding.cvss_score`), a template (`[{{ finding.severity \| upper }}] {{ finding.title }}`) or a constant |
| target | a tracker field id from the create metadata (system or custom), with its schema |
| direction | `out`, `in`, `both` (templates and constants only flow out) |
| sync | `create` (only on create), `always`, `preserve_edits` |
| winner | `openctem`, `tracker`, `last_writer` (two-way fields) |
| transform | value map (by allowed value name, sent by id), user (OpenCTEM user to tracker account, fallback account), date, number (rounding), list (labels or multi-select, prefix), join |

### 2.2 Attribute catalog

One list in code (`pkg/domain/ticketmap/catalog.go`). Each attribute has a type, a **data tier** (`title_only`,
`summary`, `full`) and a fixed **inbound capability**:

| Capability | Attributes | Effect of a tracker change |
|---|---|---|
| never | severity, scores, status, text, CVEs, asset | ignored |
| assign | assignee | the assignee, when the account maps to a member who may be assigned |
| request | SLA deadline, task due date | an SLA-extension request, decided by a person |
| note | priority class, task priority | a timeline note; never changes severity or priority |

The stored spec cannot widen a capability: validation refuses it and the engine ignores it.

### 2.3 Templates

`{{ path | filter:arg }}` only. Paths come from the catalog of the profile's object kind; filters are `join`,
`truncate`, `date`, `default`, `upper`, `lower`, `first`, `count`. No loops, conditionals, calls, includes or
variables. Values above the profile's data level are removed before rendering, so a template cannot reach them.
Rendering is followed by **redaction** (the shared secret redactor) and encoding for the tracker's markup; neither
can be turned off by a profile.

### 2.4 Status map

Outbound: each OpenCTEM state (finding: `new`, `confirmed`, `in_progress`, `fix_applied`, `verified`,
`verification_failed`, `false_positive`, `accepted`, `duplicate`, `regressed`, `acceptance_expired`; task: `open`,
`in_progress`, `fix_claimed`, `verifying`, `done`, `blocked`, `archived`) targets one workflow status with the
resolution and the other transition-screen values. The engine finds the **shortest transition path** through the
workflow (BFS, at most 8 steps) and fills every required screen field from the target; an unreachable status or a
missing required value is an error, never a guess.

Inbound: ordered rules match a status (or a category) and optionally a resolution, and yield an intent:

| Intent | Default rule | What it does |
|---|---|---|
| `fix_claim` | Done | `fix_applied` + verification |
| `request_accept` | Done + Won't Do / Won't Fix | risk-acceptance request (four-eyes) |
| `request_fp` | Done + Cannot Reproduce | false-positive request (four-eyes) |
| `suggest_duplicate` | Done + Duplicate | a duplicate suggestion |
| `in_progress` | In Progress | `in_progress` through the legal path |
| `reopen` | Reopened | back to work, queued retest cancelled |
| `ignore` | To Do, anything unmapped | nothing; unmapped statuses raise a health note |

A decision table turns an intent and the object's current state into a command (`DecideFinding`): an issue closed
while OpenCTEM still verifies keeps the claim (no ping-pong), a closed finding is never reopened from the tracker,
and the request intents always need approval. Our own transitions are recognized by the integration's account and
by the last pushed status within 10 minutes (`IsEcho`). A task's state derives from its members
(`DeriveTaskState`); a task with mixed members shows In Progress with a progress comment.

Also in the status map: a label while a claimed fix is verified (`openctem:verifying` by default), a label on SLA
breach, and the regression policy (a new linked issue by default, or reopen).

## 3. Validation and drift

On save and before publish, against the live create fields and workflow: required fields covered, values in the
allowed values, type compatibility, one writer per field and one inbound row per attribute, inbound only where the
catalog allows, invertible two-way transforms, attributes above the data level, every status target present and
reachable with its required fields, inbound rules naming existing statuses, unmapped statuses. Errors block
publishing; a draft may carry them. A tracker that cannot be reached blocks publishing.

Drift compares the published snapshot with the tracker now: a mapped field removed, renamed (kept by id), an
allowed value removed, a new required field, a workflow status removed. Any error marks the profile drifted.

## 4. API

Under `/api/v1/integrations` (module integrations): `GET ticket-mappings/catalog`, `GET|POST ticket-mappings`,
`GET|DELETE ticket-mappings/{mapping_id}`, `PUT|DELETE …/draft`, `POST …/publish` (step-up), `POST …/rollback`,
`POST …/dry-run` (step-up), `GET …/versions`, `GET …/diff`, `POST …/verify`, `POST …/drift`, `GET …/export`,
`POST …/import`, `POST …/copy`, `POST …/suggest`, `POST …/simulate`, `POST …/preview`, `POST …/inbound-preview`,
and `GET {id}/jira/issue-types`, `GET {id}/jira/metadata`. Reads need `integrations:read`; every change and both
previews need `integrations:manage`.

## 5. Security

- **Tenant isolation:** every query carries `tenant_id`; an integration of another organization is "not found";
  profiles are unique per destination inside the organization.
- **Data scope:** a preview renders only an object the caller can see (404 otherwise); task members are listed
  through the caller's scope.
- **No escalation inbound:** capabilities are code, re-checked at apply; requests go through the approval path.
- **Leakage:** data tiers per profile, redaction after rendering, encoding, secret findings never expose more
  than the masked value.
- **Change control:** edits need `integrations:manage`, publish and dry-run switches a recent step-up; every change
  is audited with a before/after diff (`ticket_mapping.*`).
- **Bounded input:** documents ≤ 256 KiB, unknown keys refused, ≤ 60 rows, value maps ≤ 100 entries, templates
  ≤ 4,000 characters; tracker metadata reads are paginated and bounded.

## 6. Plan

| Step | Content | State |
|---|---|---|
| 1 | Model, validation, metadata discovery, preview, simulator, presets, import/export, API | implemented |
| 2 | Outbound engine: create from the published profile and status moves along its workflow path (findings); dry run; no retry on refusals. Field updates on change, task issues and labels follow | implemented (findings: create + status) |
| 3 | Inbound engine: field commands and status intents through the service paths | designed |
| 4 | Console: two-column mapper, workflow mapper with simulator, preview, history and diff, health | implemented |
| 5 | Nightly drift check with a health banner and notification | designed |
