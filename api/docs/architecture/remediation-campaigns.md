# Remediation Campaigns

> Group a set of findings into a single tracked remediation effort — "fix all
> Log4j" — with an owner, a deadline, and live progress. This is the
> **Mobilization** pillar of the CTEM loop.

## What a campaign is

A `remediation_campaign` (table created in migration `000125`) ties together:

- a **scope** — a `finding_filter` (JSONB) describing which findings belong to
  the campaign (by severity, CVE, source, etc.);
- **lifecycle** — `draft → active → (paused) → validating → completed`, plus
  `canceled` from any non-terminal state; `validating → active` when a
  validation fails (the fix did not hold) and `completed → active` (Reopen,
  `PATCH /{id}/status {"status":"active"}`), which clears `completed_at`;
- **progress** — `finding_count`, `resolved_count`, and a derived `progress`
  percentage;
- **ownership & timeline** — `assigned_to` / `assigned_team`, `start_date`,
  `due_date`;
- **outcome** — `risk_score_before` / `risk_score_after` / `risk_reduction`:
  reserved for a measured risk value and left unset until one exists (they
  once held finding counts, which overflowed at 1,000 findings; migration
  `remediation_campaign_version` cleared them);
- **version** — the optimistic-concurrency token (see "Saves" below).

## Finding membership is filter-based

A campaign does **not** hold an explicit join table of finding IDs. Instead it
stores a `finding_filter` and the membership is *evaluated on demand* against
the live `findings` table. This keeps a campaign automatically in sync as new
matching findings arrive and as existing ones are resolved — no membership
bookkeeping, no drift.

### Supported `finding_filter` keys

The filter decides which findings a resolve changes, so it is parsed strictly
(`internal/app/exposure/campaign_filter.go`): an unknown key, a key given in
both its singular and plural form, a value that is not a string or a list of
strings, or a value that does not parse is refused with 400 on create and
update. A condition is never dropped, because dropping one widens the set
(`{"asset_id":"bad","severity":"critical"}` used to mean every critical
finding of the organization).

| Key                    | Maps to              | Example                         |
|------------------------|----------------------|---------------------------------|
| `severities` / `severity` | severity filter   | `["critical","high"]`           |
| `cve_ids` / `cve_id`   | CVE filter (`CVE-YYYY-NNNN…`) | `"CVE-2021-44228"`     |
| `sources` / `source`   | finding source       | `["sca","dast"]`                |
| `statuses` / `status`  | scope narrowing      | `["confirmed"]`                 |
| `finding_ids` / `finding_id` | linked findings (UUIDs) | `["<uuid>"]`           |
| `asset_id`             | single asset (UUID)  | `"<uuid>"`                      |
| `tool_name`            | tool name            | `"trivy"`                       |
| `search`               | title/description/path | `"log4j"`                     |
| `remediation_key`      | a solution family (alone, no other key) | `"sol:…"`    |

The tenant is always pinned, so counts are tenant-isolated regardless of the
filter contents. A campaign has **scope** only when a condition other than a
status narrows it: an empty filter, or a status alone ("every new finding" is
the whole organization), tracks nothing and cannot resolve. A filter stored
before the strict check that no longer parses is treated the same way, and a
resolve answers 400 until its scope is edited.

### Resolve

`POST /remediation/campaigns/{id}/resolve` needs `findings:remediation:write`
and `findings:fix_apply` (a fix claim on each finding), works only on an
`active` or `validating` campaign, and marks fixed only the open findings in
the caller's data scope (`ListFindingIDs`), behind the bulk abuse guard
(`remediation.CampaignFilterResolver`).

## Progress accounting

`progress = resolved_count / finding_count × 100`, where:

- `finding_count` = findings matching the filter (any status);
- `resolved_count` = those whose status is in the **closed** category —
  `resolved`, `false_positive`, `accepted`, `duplicate`
  (`vulnerability.ClosedFindingStatuses()`).

"Closed" rather than only "resolved" is deliberate: a finding that was accepted
as risk or marked a false positive is no longer outstanding remediation work.

### When progress is recomputed

| Trigger                              | Path                                                |
|--------------------------------------|-----------------------------------------------------|
| Campaign created                     | seeded once so it never reads 0/0 (best-effort)     |
| Campaign read (`GET /`, `GET /{id}`) | computed live for the response, never persisted     |
| Manual refresh (`POST /{id}/refresh`)| recomputed + auto-complete + persisted              |
| Background reconcile                 | `RemediationProgressController`, every 30 min       |

The controller (`internal/infra/controller/remediation_progress.go`) walks
non-terminal campaigns across all tenants, least recently reconciled first
(`last_reconciled_at`, never-reconciled first), and writes their counters with
a narrow update that also stamps `last_reconciled_at`, changed or not, so a
backlog larger than one batch rotates instead of starving. The counter update
never touches status, dates or the version. It is registered in
`cmd/server/workers.go` whenever the campaign service is available.

### Done means fixed

A campaign is **done** when every finding is closed **and at least one is
verified fixed** (`resolved`; `verified_count` in the response, computed with
the counts). A campaign whose findings were all accepted, marked false
positive or folded as duplicates fixed nothing and is not done
(`Campaign.IsDone`).

- Manual completion of a campaign that is not done is refused (400,
  `ErrCampaignNotDone`) unless the request sets `close_with_open_members`;
  the console asks first and sends it only after the person confirms. The
  audit row carries `trigger=manual_with_open_members`, `open_findings` and
  `verified_findings`, at medium severity.
- A Jira epic moved to Done completes the campaign only when it is done (the
  counts are recomputed first); otherwise the campaign stays as it is and the
  refusal is logged. A closed ticket is a claim, not evidence.
- A campaign's due date only tightens: an update may set a first due date or
  move it to an earlier day; a later day or clearing it is refused
  (`ErrCampaignDeadlineOnlyTightens`).

### Auto-complete

When a campaign is done (above) and it is `active` or `validating`, the
reconcile (and the manual refresh) transitions it
to `completed` through a versioned save: a Pause or Cancel made since the
reconciler read the campaign wins, and the completion is skipped. An empty campaign
(`finding_count == 0`) is never auto-completed — an empty campaign is a
misconfiguration, not an accomplishment (`Campaign.TryAutoComplete`).

## API

Base path `/api/v1/remediation/campaigns` (permissions: `remediation:read` /
`remediation:write`):

| Method | Path             | Purpose                                  |
|--------|------------------|------------------------------------------|
| GET    | `/`              | list (status / priority / search filters)|
| POST   | `/`              | create                                   |
| GET    | `/{id}`          | get (progress computed live, not stored) |
| PATCH  | `/{id}`          | update name/description/priority/tags/due (optional `version`)|
| PATCH  | `/{id}/status`   | transition lifecycle (optional `version`)|
| POST   | `/{id}/refresh`  | recompute progress + auto-complete now   |
| DELETE | `/{id}`          | delete                                   |

## Saves

Every full save is optimistic: `UPDATE … WHERE version = <read version>`,
bumping `version`. A save on a stale copy changes nothing and answers
`409 Conflict`; a `PATCH` may also send the `version` the person edited, so a
second tab cannot overwrite the first. Reads never write. Priority is one of
`critical`, `high`, `medium`, `low` (validated by the API and a database
CHECK); an empty name is refused. A campaign is overdue only after the end of
its due day (UTC): the due date is a day, so a campaign due today is not yet
late.

## Audit trail

Every change to a campaign is written to `audit_logs` (resource type
`remediation_campaign`), through `RemediationCampaignService.SetAuditLogger`:

| Action                                  | When                                                        |
|-----------------------------------------|-------------------------------------------------------------|
| `remediation_campaign.created`          | `POST /`                                                    |
| `remediation_campaign.updated`          | `PATCH /{id}`, with before/after of only the changed fields |
| `remediation_campaign.status_changed`   | any lifecycle move (see `trigger` below)                    |
| `remediation_campaign.deleted`          | `DELETE /{id}`                                              |

A status change carries `trigger` (`manual` for `PATCH /{id}/status`,
`manual_with_open_members` for an explicit completion of a campaign that is
not done, `auto_complete` when it became done, `jira_epic` when the linked
epic was closed on a done campaign), `finding_count`, `resolved_count`, and on
completion `open_findings` and `verified_findings`. A completion with open or
no verified findings is logged at medium severity. Automatic moves are
attributed to the actor `system`. The audit row is always filed under the
campaign's tenant; an audit write failure is logged and never fails the change.

A manual completion recomputes the counts first, so `progress` and
`open_findings` reflect the findings at that moment, not
the last reconcile. Completing does not change progress: a campaign completed
with 0 of 4 findings closed reads "Completed, 0%", because that is what
happened.

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

## Solution-family campaigns (from a remediation group)

A campaign can be scoped to a **remediation-group key** (RFC-015 — a "solution
family": every finding that one fix resolves) instead of a generic filter. Create
it exactly like any campaign, with the key in the filter:

```
POST /api/v1/remediation/campaigns
{ "name": "Upgrade openssl", "finding_filter": { "remediation_key": "sol:…" } }
```

This turns a derived group — which can only be bulk-resolved *now* — into a
**tracked** effort (assignee, due date, live progress %) that dynamically follows
the family: findings surfaced by later scans that share the key roll into the
campaign automatically.

A keyed campaign does **not** use the generic `FindingFilter` path. The key isn't
expressible as a `FindingFilter`, so both progress and resolution run through a
separate `CampaignKeyResolver` seam:

- **Progress** — counted from the `finding_remediation_keys` side-table
  (`KeyRepository.CountByKey` → total + resolved), not the findings filter.
- **Resolve** — delegated to the same guarded group-resolve path as the standalone
  "resolve group" action (`GroupService.ResolveGroup`, abuse-guarded, non-pentest).
  Every campaign resolve, keyed or not, is a "mark fixed" that never closes a
  finding (see `finding-status-lifecycle.md`, "Mark fixed").

**Safety invariant:** a keyed campaign's resolve branches *before* the generic
filter is ever built, and **fails closed** if the key resolver is unwired. This is
deliberate — an unknown `remediation_key` would otherwise map to a tenant-only
`FindingFilter` and resolve every finding in the tenant. The key path is the only
path a keyed campaign can take.

## Planned (not yet shipped)

- **Bidirectional Jira sync for campaigns** — push a campaign to a Jira epic and
  reflect epic status back, via the RFC-006 Phase 3e `WorkItem` seam. The
  finding-level Jira sync already exists; the campaign-level epic mapping does
  not.
- **Explicit membership override** — pinning/excluding individual findings on
  top of the filter.
- **Measured risk reduction** — the risk fields stay unset until campaign
  risk is measured (a severity- or score-weighted value, not a count).
