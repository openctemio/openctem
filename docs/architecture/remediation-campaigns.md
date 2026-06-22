# Remediation Campaigns

> Group a set of findings into a single tracked remediation effort — "fix all
> Log4j" — with an owner, a deadline, and live progress. This is the
> **Mobilization** pillar of the CTEM loop.

## What a campaign is

A `remediation_campaign` (table created in migration `000125`) ties together:

- a **scope** — a `finding_filter` (JSONB) describing which findings belong to
  the campaign (by severity, CVE, source, etc.);
- **lifecycle** — `draft → active → (paused) → validating → completed`, plus
  `canceled` from any non-terminal state;
- **progress** — `finding_count`, `resolved_count`, and a derived `progress`
  percentage;
- **ownership & timeline** — `assigned_to` / `assigned_team`, `start_date`,
  `due_date`;
- **outcome** — `risk_score_before` / `risk_score_after` / `risk_reduction`,
  stamped on completion.

## Finding membership is filter-based

A campaign does **not** hold an explicit join table of finding IDs. Instead it
stores a `finding_filter` and the membership is *evaluated on demand* against
the live `findings` table. This keeps a campaign automatically in sync as new
matching findings arrive and as existing ones are resolved — no membership
bookkeeping, no drift.

### Supported `finding_filter` keys

All keys are optional; unknown keys are ignored. Each accepts a single string
or an array of strings.

| Key                    | Maps to              | Example                         |
|------------------------|----------------------|---------------------------------|
| `severities` / `severity` | severity filter   | `["critical","high"]`           |
| `cve_ids` / `cve_id`   | CVE filter           | `"CVE-2021-44228"`              |
| `sources` / `source`   | scanner source       | `["trivy","nuclei"]`            |
| `statuses` / `status`  | scope narrowing      | `["confirmed"]`                 |
| `asset_id`             | single asset         | `"<uuid>"`                      |
| `tool_name`            | tool name            | `"trivy"`                       |
| `search`               | title/description/path | `"log4j"`                     |

The tenant is always pinned, so counts are tenant-isolated regardless of the
filter contents. An empty filter scopes the campaign to *all* of the tenant's
findings (a misconfiguration, not an error).

## Progress accounting

`progress = resolved_count / finding_count × 100`, where:

- `finding_count` = findings matching the filter (any status);
- `resolved_count` = those whose status is in the **closed** category —
  `resolved`, `verified`, `false_positive`, `accepted`, `accepted_risk`,
  `duplicate` (`vulnerability.ClosedFindingStatuses()`).

"Closed" rather than only "resolved" is deliberate: a finding that was accepted
as risk or marked a false positive is no longer outstanding remediation work.

### When progress is recomputed

| Trigger                              | Path                                                |
|--------------------------------------|-----------------------------------------------------|
| Campaign created                     | seeded once so it never reads 0/0 (best-effort)     |
| Campaign fetched (`GET /{id}`)       | recomputed live, persisted if changed (best-effort) |
| Manual refresh (`POST /{id}/refresh`)| recomputed + auto-complete + persisted              |
| Background reconcile                 | `RemediationProgressController`, every 30 min       |

The controller (`internal/infra/controller/remediation_progress.go`) walks
every non-terminal campaign across all tenants (oldest-updated first), refreshes
its counts, and persists only the ones that changed. It is registered in
`cmd/server/workers.go` whenever the campaign service is available.

### Auto-complete

When **all** of a campaign's findings are resolved
(`finding_count > 0 && resolved_count >= finding_count`) and the campaign is
`active` or `validating`, the reconcile (and the manual refresh) transitions it
to `completed` and stamps the risk-reduction metric. An empty campaign
(`finding_count == 0`) is never auto-completed — an empty campaign is a
misconfiguration, not an accomplishment (`Campaign.TryAutoComplete`).

## API

Base path `/api/v1/remediation/campaigns` (permissions: `remediation:read` /
`remediation:write`):

| Method | Path             | Purpose                                  |
|--------|------------------|------------------------------------------|
| GET    | `/`              | list (status / priority / search filters)|
| POST   | `/`              | create                                   |
| GET    | `/{id}`          | get (refreshes progress live)            |
| PATCH  | `/{id}`          | update name/description/priority/tags/due|
| PATCH  | `/{id}/status`   | transition lifecycle                     |
| POST   | `/{id}/refresh`  | recompute progress + auto-complete now   |
| DELETE | `/{id}`          | delete                                   |

## Layering

| Layer    | File                                                                 |
|----------|----------------------------------------------------------------------|
| Domain   | `pkg/domain/remediation/campaign.go`                                 |
| Service  | `internal/app/exposure/remediation_campaign.go`                      |
| Repo     | `internal/infra/postgres/remediation_campaign_repository.go`         |
| Handler  | `internal/infra/http/handler/remediation_campaign_handler.go`        |
| Routes   | `internal/infra/http/routes/remediation.go`                          |
| Controller | `internal/infra/controller/remediation_progress.go`                |

The service depends on the finding repository only through the narrow
`FindingCounter` interface (`Count(ctx, FindingFilter)`), wired in
`cmd/server/services.go`. When no counter is wired the service degrades to plain
CRUD with zero progress.

## Planned (not yet shipped)

- **Bidirectional Jira sync for campaigns** — push a campaign to a Jira epic and
  reflect epic status back, via the RFC-006 Phase 3e `WorkItem` seam. The
  finding-level Jira sync already exists; the campaign-level epic mapping does
  not.
- **Explicit membership override** — pinning/excluding individual findings on
  top of the filter.
- **Per-severity risk weighting** — `risk_reduction` is currently a simple
  resolved/total count, not a severity- or EPSS-weighted score.
