# Finding lifecycles (organization sub-statuses and schemes)

Design: [RFC-110](../rfcs/RFC-110-tenant-lifecycles.md). The canonical statuses and the transition engine
they sit on: [finding-status-lifecycle.md](finding-status-lifecycle.md).

An organization adds its own labels and rules on top of the canonical finding lifecycle. The canonical status
stays the platform invariant: every metric, the SLA, the CI gate, the exports and every security rule read
it. A sub-status is a label inside one canonical status; a lifecycle scheme can only add constraints to the
moves the platform allows.

## Shipped

### Sub-status catalog and the findings column

| Piece | Where |
|---|---|
| Tables `lifecycle_sub_statuses`, `lifecycle_schemes`, `lifecycle_scheme_versions` | migration `002767_lifecycle_catalog` |
| `findings.sub_status_id` and the composite foreign key `(tenant_id, sub_status_id, status)` | migrations `002767`, `002768_findings_sub_status_fk` (`NOT VALID`), `002769_findings_sub_status_fk_validate` |
| Partial index on findings that carry a sub-status | `002770_findings_sub_status_index` (built concurrently) |
| Domain: `SubStatus`, validation, catalog repository interface | `pkg/domain/findinglifecycle/substatus.go` |
| Repository | `internal/infra/postgres/lifecycle_sub_status_repository.go` |

Rules the database enforces on its own, whatever the code does:

- A sub-status binds one of the eight canonical statuses. A closed status (resolved, false positive,
  accepted, duplicate) binds one of its own closure reasons; an open status binds none.
- Its tenant, kind, canonical status, closure reason and key never change
  (`trg_lifecycle_sub_statuses_category`). A rename keeps its meaning; a sub-status is archived, never
  deleted.
- A finding's sub-status belongs to its own tenant and current status (the composite foreign key).
- Any writer that moves the status without naming a sub-status of the new status lands on the default
  label (NULL), and so does a change of closure reason that no longer fits the bound one
  (`trg_findings_sub_status_settle`). The platform's bulk writers, the scanners, the expiry jobs and the
  approval flow therefore work unchanged. An explicit choice that does not fit is refused.
- A lifecycle version, once published, never changes; a published version may only become superseded,
  and there is at most one draft per scheme.
- Metrics never read the sub-status: `TestMetricQueriesNeverReadSubStatus` fails when a dashboard, metric,
  SLA or risk repository mentions it.

### Definitions API

| Piece | Where |
|---|---|
| Permission `findings:lifecycles:write` (owner and admin) | `pkg/domain/permission`, migration `finding_lifecycles_permission` |
| Routes `/api/v1/lifecycle-sub-statuses`, `/api/v1/lifecycles` | `internal/infra/http/routes/finding_lifecycles.go`, `handler/finding_lifecycle_handler.go` |
| Service: catalog, schemes, drafts, validation, publish, roll back | `internal/app/findinglifecycle/service.go` |
| Schemes and versions | `pkg/domain/findinglifecycle/scheme.go`, `internal/infra/postgres/lifecycle_scheme_repository.go` |
| Limits `lifecycle_sub_statuses` and `lifecycle_schemes` (unlimited unless set; see [limits](limits.md)) | `pkg/domain/limits/limits.go` |

- A draft is edited with `If-Match: <spec_hash>`, so two editors never overwrite each other; the answer
  carries the validation against the current catalog.
- Publishing compiles the draft (an invalid one answers 422 with the issues), needs a recent sign-in
  (step-up), supersedes the version in force and is audited (`lifecycle.published`, high, with the old and
  new spec hashes). Publishing an older version copies it into a new version and publishes that (a roll
  back); history stays linear.
- A sub-status a published lifecycle uses cannot be archived. Archiving a lifecycle stops it applying.

### Moves under a lifecycle

Every status path decides a move with the platform engine first and then the scheme selected for the
finding (`findinglifecycle.EvaluateMove`, `internal/app/finding/lifecycle_moves.go`):

| Path | How the lifecycle applies |
|---|---|
| `PATCH /findings/{id}/status` | takes `sub_status_id` (the sub-status the move lands on; with the current status, a label move inside it) and `fields` (the inputs the lifecycle requires) |
| `POST /findings/bulk/status`, remediation group and campaign resolves, Jira inbound | each finding decided on its own, landing on the target's default sub-status |
| `/actions/fix-applied`, `/actions/verify`, `/actions/reject-fix` and the by-filter forms | the same narrowing; action routes take no fields, so a move that requires them is refused there |
| Approval requests (false positive, accepted) | the request itself is narrowed (permission, note length, actor kind); a request that would need fields is refused until requests carry them |
| GitHub issue webhook | decided as the ticket actor |
| Assign to owners | starts work (confirmed → in_progress) only when the lifecycle lets it; the assignment happens either way |
| `GET /findings/{id}/transitions`, `POST /findings/transitions/preview` | list the moves with the sub-status each lands on, the transition, the longer note and the fields it needs, and the organization's reasons for a refusal |

- **A sub-status changes only through these moves**: no route writes `findings.sub_status_id` directly. Each
  move is on the timeline with the old and new sub-status, the lifecycle version that decided it
  (`lifecycle:<version id>@<n>`, or `platform:1` without a scheme), the transition and the field values.
- **Platform moves** (a covered scan, a retest, a VEX statement, expiry, a regression) do not ask the
  lifecycle and land on the default label.
- The caller's permissions reach the service through the request context
  (`middleware.PermissionCheckContext`, `shared.CallerHasPermission`), so `require_permission` reads the
  same fresh permissions as the route gates; delegated actors hold none.
- Published schemes are compiled once per version id and cached in process; each move reads which
  versions are published (one query), so a publish or an archive applies to the next move.
- `TestFindingLifecycle_CannotBypassTheEngine_DB` drives the real routes: listed moves never pass a platform
  rule (verify permission, evidence matrix, fix-claim rules, four-eyes, canonical edges), the lifecycle's own
  guards bind, and another organization's sub-status is refused.

### Console: Settings → Findings → Finding lifecycle

`web/src/app/(dashboard)/settings/finding-lifecycle/page.tsx`, components in
`web/src/features/findings/components/lifecycle/`, API client in
`web/src/features/findings/api/use-finding-lifecycles.ts`.

- **Sub-statuses tab:** a lane per canonical status with its sub-statuses (add, rename, Vietnamese name,
  colour from the fixed palette, reorder, archive, reactivate). A closed status's sub-status picks its
  closure reason once; the key and closure reason are read-only afterwards.
- **Lifecycles tab:** the organization's lifecycles; for the selected one, the draft editor (sub-statuses
  used, the default label per status, `person_moves`, the listed moves with conditions, a longer note,
  required fields, a required permission and refused actor kinds), a check panel showing the validator's
  errors and warnings, publish, and the version history with roll back.
- Saving a draft sends the `spec_hash` it read as `If-Match`; a 409 tells the editor someone else changed
  the draft and offers a reload, never an overwrite. Publish and roll back go through the shared API
  client, which opens the step-up dialog on `STEP_UP_REQUIRED` and retries once.
- Everyone with `findings:read` sees the page read-only; changing needs `findings:lifecycles:write`. Plan
  usage (`GET /organization/plan`, administrators) shows "used of limit" and disables adding at the limit;
  a `PLAN_LIMIT` refusal from the API is shown in words either way. The API stays the only authority.
- Sub-status colours only tint a small dot (`web/src/lib/sub-status-colors.ts`); names are plain text,
  rendered escaped.

## Planned (RFC-110 §11)

- The pure engine layer (scheme spec, validator, guards, context selection) and its property test (in
  review).
- Sub-statuses and fields on approval requests; the list filter by sub-status; the simulator.
- Sub-statuses in the finding drawer, list and bulk actions.
- Templates, extra approval steps, ticket mapping by sub-status, the flow report.
