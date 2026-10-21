# Ticket create policy

Which findings become tracker issues automatically, per Jira integration. The
policy decides **whether** an automatic create happens; routing rules decide
**where**, mapping profiles decide **what** the issue contains, and the outbound
gate decides what may leave the platform. It is a noise filter, not a security
control: it can only hold a finding back, and every create it lets through
still passes the outbound (egress / TLP) gate.

## Policy

One row per integration in `ticket_create_policies` (migration
`ticket_create_policy`); no row means the defaults.

| Field | Default | Meaning |
|---|---|---|
| `min_severity` | `medium` | severity at or above passes (`info` lets everything through, `none` included) |
| `min_priority_class` | `P2` | priority class at or above passes (`P0` highest); empty = not used |
| `always_kev` | `true` | a finding in the KEV catalog passes whatever its severity |
| `daily_cap` | `200` | automatic creates per integration and UTC day; `0` = no cap |

A finding passes when it is open **and** (severity ≥ `min_severity` **or**
priority class ≥ `min_priority_class` **or** (`always_kev` and in KEV)). Any one
signal is enough, so a finding that matters by one measure is never held by
another. `pkg/domain/ticketpolicy` holds the evaluation; the preview's SQL
predicate is built from the same lists, and a database test checks the two
agree.

## Where it applies

| Path | Policy | Daily cap |
|---|---|---|
| Workflow `create_ticket` action (Jira) | yes: below → hold, the step succeeds with `held: true` | yes: over → hold `daily_cap` |
| Release job (held findings that now pass) | yes | yes |
| A person's **Create ticket** (`POST /findings/{id}/create-ticket`) | below → `409 TICKET_BELOW_THRESHOLD` unless `confirm_below_threshold: true`; a confirmed create is audited (`ticket.created_below_threshold`) | no |
| Pentest campaign tickets, remediation task issues, campaign epics | no (deliberate actions on curated content) | no |
| GitHub issues | not yet | not yet |

A successful create removes the finding's hold on that integration.

## Holds

`ticket_create_holds` keeps one row per (integration, finding) the automatic
path held back, with the reason:

- `below_threshold`: the policy did not pass it;
- `daily_cap`: it passed, but today's cap was reached;
- `create_failed`: the create was refused or failed; `detail` is a platform
  code (`egress:<reason>`, `invalid_destination`, `integration_unavailable`,
  `tracker_error`), never upstream text.

The finding shows the hold ("Not sent to Jira — below the create policy") next
to its ticket links, with **Create anyway** for people who may create tickets.
The policy dialog shows the held counts by reason and today's creates.

## Release job

`ticket-hold-release` (every 2 minutes, one leader through the controller
lease, module `integrations`) re-checks at most 200 holds per run, most severe
first, when:

- the finding changed since the last check (`findings.updated_at`, bumped by
  rescoring, KEV escalation and edits) — so a finding re-scored from Low to High
  or newly listed in KEV is created then;
- the policy changed since the last check — so loosening it releases held
  findings, bounded by the daily cap;
- a `daily_cap` hold on a new UTC day;
- a `create_failed` hold after an hour.

A closed finding, or one that already has an active issue on the integration,
drops its hold. A loosened policy therefore never creates more than the daily
cap per day; the preview shows the backlog before saving. Tightening a policy
never closes or changes existing issues. Counter rows older than seven days are
deleted by the same job.

## API

| Route | Gate | Notes |
|---|---|---|
| `GET /api/v1/integrations/{id}/ticket-create-policy` | `integrations:manage` | policy (or defaults, `stored: false`), held counts by reason, created today |
| `PUT /api/v1/integrations/{id}/ticket-create-policy` | `integrations:manage` | validated; audited `ticket_create_policy.updated` with before and after |
| `POST /api/v1/integrations/{id}/ticket-create-policy/preview` | `integrations:manage` | counts only: findings first seen in the last 30 days that pass, holds it would release |
| `GET /api/v1/findings/{id}/ticket-holds` | `findings:read` + the finding data-scope route guard | the finding's holds |
| `POST /api/v1/findings/{id}/create-ticket` | unchanged (`findings:write`) | `confirm_below_threshold` |

## Security

- **Hidden critical findings by misconfiguration:** OR semantics, KEV always on
  by default, holds visible on the finding and counted on the policy, Create
  anyway always available, nothing closed when the policy tightens.
- **Authorization:** the policy routes are `integrations:manage` (the counts
  are organization-wide aggregates, never finding content); the integration is
  resolved within the caller's tenant (another tenant's id is 404). A finding's
  holds follow its data scope (404 out of scope).
- **Tenant isolation:** composite foreign keys `(tenant_id, integration_id)`
  and `(tenant_id, finding_id)` on every table, `tenant_id` in every tenant
  query. The release job's system-wide listing carries each row's tenant into
  the tenant-scoped create.
- **Floods and backfills:** the daily cap bounds automatic creates and every
  release; a run handles at most 200 holds.
- **Egress:** the policy runs before the outbound gate and can never widen it;
  a refused release is kept as `create_failed` with the gate's reason code.
- **Audit:** policy changes (before and after) and confirmed creates below the
  policy.

Design research: `research/224-ticket-creation-filters` (internal notes).
Related: [ticketing (Jira)](ticketing-integration.md),
[ticket field mapping](ticket-field-mapping.md).
