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
| Tables `lifecycle_sub_statuses`, `lifecycle_schemes`, `lifecycle_scheme_versions` | migration `002712_lifecycle_catalog` |
| `findings.sub_status_id` and the composite foreign key `(tenant_id, sub_status_id, status)` | migrations `002712`, `002713_findings_sub_status_fk` (`NOT VALID`), `002714_findings_sub_status_fk_validate` |
| Partial index on findings that carry a sub-status | `002715_findings_sub_status_index` (built concurrently) |
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

## Planned (RFC-110 §11)

- The pure engine layer (scheme spec, validator, guards, context selection) and its property test.
- The catalog API with the `findings:lifecycles:write` permission and plan limits; the finding resource
  and list filter.
- Schemes and versions (validate, simulate, publish with step-up, rollback), and the tenant layer on every
  status path.
- Settings → Findings → Lifecycle, and sub-statuses in the finding drawer, list and bulk actions.
- Templates, extra approval steps, ticket mapping by sub-status, the flow report.
