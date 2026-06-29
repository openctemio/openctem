# Ticketing Integration (Jira) — Mobilization

> **Status**: **Bidirectional status sync functional** (per-tenant, opt-in).
> Create + inbound + outbound all work; configurable mapping per integration.
> Provider abstraction (ServiceNow/GitHub) is designed in
> [RFC-006](../rfcs/RFC-006-ticketing-provider-and-mapping.md) /
> [RFC-006 Phase 3](../rfcs/RFC-006-phase-3-bidirectional-sync.md).
> Ticketing is the CTEM **Mobilization** pillar.

## Overview

OpenCTEM links findings to external tickets and keeps status in sync **both ways**:

- **Create** a Jira ticket from a finding (`POST /api/v1/findings/{id}/create-ticket`)
  into the tenant's **default project** (or an explicit `project_key`); the
  project picker is fed by `GET /api/v1/integrations/jira/projects`.
- **Link / unlink** an existing ticket to a finding.
- **Inbound** (`POST /api/v1/webhooks/incoming/jira?tenant=<id>`): a Jira status
  change updates the finding status (and can trigger a verification scan).
- **Outbound** (RFC-006 Phase 3): a finding status change in OpenCTEM transitions
  the linked Jira issue to match. **Opt-in per integration** (`sync_enabled`,
  default off).

A finding ↔ ticket link is stored as a URL in `finding.WorkItemURIs()` (the Jira
issue key is parsed from the `/browse/<KEY>` URL).

## Per-tenant client resolution

Outbound ticketing builds a Jira client **per tenant** from that tenant's
connected integration — there is no single global Jira client. This mirrors the
per-tenant SMTP resolver.

```
SyncService.CreateTicketFromFinding(tenantID, …)
        │
        ▼
SyncService.resolveClient(tenantID)
   ├─ static client set?  (tests) ──► use it
   └─ else ClientResolver.Resolve(tenantID)
            │
            ▼
   IntegrationClientResolver  (internal/infra/jira/resolver.go)
     1. integrationRepo.ListByProvider(tenantID, ProviderJira)
     2. pick first StatusConnected integration
     3. decrypt credentials (AES-256-GCM / APP_ENCRYPTION_KEY)
     4. build *infra/jira.Client → adapt to app/jira.Client
```

The same resolver implements `MappingResolver.ResolveMapping(tenantID)` for
outbound sync (per-tenant status maps + `sync_enabled` from `config.ticketing`).

No connected, usable integration → `ErrNoTicketingIntegration` (wraps
`ErrValidation` → HTTP 400, not 500). Misconfigured integrations are skipped
(logged), not fatal.

### Credential format

Jira Cloud REST uses basic auth = **account email + API token**. The connect
dialog stores both, packed as JSON in the encrypted `credentials` field:

```json
{ "email": "sec@acme.com", "api_token": "<token>" }
```

The resolver also accepts (in priority order): JSON `{email, api_token}`; a bare
token with the email from `config`/`metadata["email"]`; or a legacy packed
`"email:token"`. The integration's `base_url` is the Jira site
(`https://acme.atlassian.net`), validated against SSRF (`pkg/httpsec`).

## Setup (operator)

1. In Jira, create an API token (Atlassian account → Security).
2. In OpenCTEM: Settings → Integrations → Ticketing → Connect, provider **Jira**.
   Enter base URL, the Atlassian account email, and the API token. Pick the
   **default destination project** from the picker — `GET /api/v1/integrations/jira/projects`
   lists the projects visible to the credentials (stored as `config.ticketing.project_key`).
3. Create a ticket from any finding via the finding actions, or the
   `create-ticket` endpoint with `{"project_key": "SEC", "issue_type": "Bug"}`.
   When the request omits `project_key`, the tenant's default project is used.
4. (Inbound) Configure a Jira webhook to
   `POST /api/v1/webhooks/incoming/jira?tenant=<tenant-id>` (HMAC via
   `JiraSecret`, fail-closed).
5. (Outbound) **Configure** on the connected integration → toggle **Bidirectional
   status sync** and, for a custom Jira workflow, map your status names.

## Outbound status sync (RFC-006 Phase 3)

When a finding's status changes **in OpenCTEM**, the linked Jira issue is moved to
match — the reverse of the inbound webhook. **Opt-in** per integration and
reliable (off the request path):

```
VulnerabilityService.UpdateFindingStatus(...)        (status actually changed
        │                                             AND finding has a ticket link)
        ▼  enqueue (best-effort)
asynq task  jira:sync_finding_status
        ▼  background worker
SyncService.SyncFindingStatus(tenantID, findingID)
   ├─ MappingResolver.ResolveMapping(tenantID)   → per-tenant status maps + sync_enabled
   │      (no Jira integration → no-op)
   └─ SyncFindingStatusToTicket(…, mapping)
        ├─ mapping.SyncEnabled == false           → no-op (opt-in gate)
        ├─ status_outbound[findingStatus] unset   → no-op (don't move the card)
        ├─ GetIssueStatus == target               → skip (echo-guard / idempotent)
        ├─ TransitionToStatus(issueKey, target)   → move the Jira card
        └─ no workflow transition to target       → AddComment (never hard-fail)
```

**Echo-safe by construction:** the inbound webhook updates findings via a
*different* path (`finding.TransitionStatus` + `findingRepo.Update`), **not**
`UpdateFindingStatus` — so a Jira-driven change never re-triggers an outbound
push. A `GetIssueStatus`-equals-target check is the secondary guard.

**Why asynq, not the notification outbox:** the notification outbox fans events
out to Slack/email by subscription; performing a Jira *transition* is an action,
so it runs on the job queue (`internal/infra/jobs/jira_sync_tasks.go`) with
retry/backoff. A Jira failure never fails the originating status change.

## Safety properties (shipped)

- **Idempotent create** (#134): a finding already ticketed in the target project
  (its `WorkItemURIs` contains `/browse/<PROJECT>-`) is not re-created.
- **Secret redaction** (#135): secret-leak findings never copy the raw value into
  a ticket; descriptions are run through redaction patterns as defense-in-depth.
- **Outbound opt-in** (#171): `sync_enabled` defaults to false — connecting an
  integration never silently writes to Jira.

## Mappings (configurable per integration)

`MappingConfig` (`internal/app/jira/mapping.go`) holds the maps. `DefaultMappingConfig()`
is the stock-Jira default; `ParseMappingConfig(integration.Config())` overlays a
tenant's `config.ticketing` overrides (partial configs only change what they
specify; invalid targets skipped). Defaults:

| Direction | Default mapping |
|-----------|-----------------|
| severity → Jira priority | critical→Highest, high→High, medium→Medium, low→Low |
| Jira status → finding (inbound) | done/resolved/closed/verified→fix_applied; in progress/in review→in_progress; open/to do/backlog/reopened→confirmed; duplicate→duplicate |
| finding → Jira status (outbound) | confirmed→To Do; in_progress→In Progress; fix_applied/resolved/verified→Done (false_positive/accepted unset by default) |

Customers with custom workflows (`In Dev / QA / Shipped / Won't Do`) set their
own names via `config.ticketing`.

### `config.ticketing` reference

```json
{ "ticketing": {
    "project_key": "SEC",
    "issue_type": "Task",
    "default_priority": "P3",
    "severity_to_priority": { "critical": "P1", "high": "P2" },
    "status_inbound":  { "Shipped": "fix_applied", "QA": "in_progress" },
    "sync_enabled":    true,
    "status_outbound": { "resolved": "Done", "false_positive": "Won't Do", "in_progress": "In Dev" },
    "routing": [
      { "match": { "scope": ["external"], "severity": ["critical","high"] }, "project_key": "EXT", "issue_type": "Security Bug" },
      { "match": { "tag": ["pci"] }, "project_key": "PCI" }
    ]
}}
```

| Key | Direction | Meaning |
|-----|-----------|---------|
| `project_key` | create | **Default destination project** when the request omits one and no routing rule matches. Empty = the request must pass `project_key`. |
| `routing` | create | Ordered rules selecting the destination project (+ optional `issue_type`) by finding/asset attributes — **first match wins**, falls through to `project_key`. See below. |
| `sync_enabled` | outbound | Master switch for OpenCTEM→Jira status push. **Default `false`.** |
| `status_outbound` | outbound | finding status → Jira status NAME. Unset finding status = no push; unreachable target = comment. Defaults cover stock Jira (To Do/In Progress/Done). |
| `status_inbound` | inbound | Jira status name → finding status (overlays defaults; case-insensitive). |
| `severity_to_priority` | create | finding severity → Jira priority. |
| `issue_type` / `default_priority` | create | defaults for new issues. |

> **Create now applies the per-tenant mapping.** `CreateTicketFromFinding`
> resolves `config.ticketing` and uses it for the destination project
> (`project_key`), issue type, and severity→priority — instead of the previous
> hardcoded `Bug` + stock priority table. With no config the defaults reproduce
> the original behavior exactly. **Destination resolution order:** explicit
> request `project_key` → first matching **routing** rule → tenant default
> `project_key` → else a validation error (we never guess where a ticket goes).

#### Routing rules

`routing` is how "each Jira project = a team / business unit" is expressed
**without making a project an asset**. Each rule has a `match` block and a
target `project_key` (+ optional `issue_type`):

- **Conditions** — `severity`, `tag` (finding-level); `scope`, `criticality`,
  `asset_group` (asset-level). Each accepts a string or array; values are
  case-insensitive. Within a condition values are **OR**'d; across conditions
  they are **AND**'d; an omitted condition is a wildcard.
- **Order matters** — the first matching rule wins; put the most specific rules
  first. A rule with no `project_key` is dropped (it could never route).
- **Asset attributes** (`scope`/`criticality`) come from the finding's asset via
  `AssetRouteResolver` (`internal/infra/jira/asset_route_resolver.go`). The
  `asset_group` dimension is parsed and matchable but **not yet populated** by
  the resolver (group-membership wiring is a follow-up) — use `scope`/
  `criticality`/`severity`/`tag` today.

> Inbound never auto-applies `false_positive`/`accepted` (they require approval),
> and every Jira "done"-like status maps to `fix_applied` (not `resolved`, which
> needs verification) — the rescan hook promotes to `resolved`. See
> [RFC-006 Phase 3 §3.6.1](../rfcs/RFC-006-phase-3-bidirectional-sync.md) for the
> full status-model rationale.

## Roadmap (RFC-006)

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Per-tenant client resolver | **Done** (#137, ui#152) |
| 1 | `MappingConfig` type + defaults (zero behaviour change) | **Done** (mapping.go) |
| 2 | Configurable mapping (`status_outbound`/`status_inbound`/`sync_enabled`) backend + UI editor | **Done** (#168 backend; UI in ui#193) |
| 2b | Wire mapping into **create** (project/issue-type/priority) + default project + project picker | **Done** (#207, ui#184) |
| 3 | Outbound status sync (asynq + echo-guard, opt-in) | **Done** (#167, #171) |
| 4a | Routing rules (severity/tag/asset scope/criticality → project_key) | **Done** (#209; UI in ui#189; asset_group dimension deferred) |
| 4b | 2nd provider (ServiceNow/GitHub) + typed `ticket_links` table | Planned (optional) |

### UI surfaces (shipped)

The full operator UI is in the `ui` repo:

| Surface | Where | PR |
|---------|-------|-----|
| Connect Jira (base URL + email + token) | Settings → Integrations → Ticketing | ui#152 |
| **Default project picker** (lists `GET /integrations/jira/projects`) + sync toggle | Configure dialog | ui#184 |
| **Mapping editor** (issue type, default priority, severity→priority, outbound status names) | Configure dialog | ui#193 |
| **Routing rules editor** (severity/scope/criticality/tag → project) | "Routing" dialog on the integration card | ui#189 |
| **Create ticket from a finding** | findings table row menu + finding **detail drawer** | ui#189 (row), ui#192 (drawer) |

> Note: an earlier roadmap entry credited a `ui#170` mapping editor that was never
> actually merged to `develop`; the real mapping/create-ticket/routing UI landed in
> ui#184/#189/#192/#193 (some recovered from a stacked-PR mishap — see git history).
> Inbound status-name mapping editor (arbitrary Jira status → finding status) is the
> one remaining UI gap; stock-Jira inbound defaults cover the common case.

Related future work (its own RFC): **Jira Assets / JSM CMDB** — pull asset
business-context to enrich prioritization, push discovered assets, link CI
objects to finding tickets. Today only the core issue API is used. A Jira
**project** is a routing destination (config), **not** an OpenCTEM asset; the
Jira *site* is the thing that can be modeled as a `web_application` asset.

## Key files

```
internal/app/jira/sync_service.go             SyncService: create, inbound webhook,
                                              SyncFindingStatus(ToTicket) (outbound), resolvers, redaction
internal/app/jira/mapping.go                   MappingConfig (severity/status maps, status_outbound, sync_enabled)
internal/infra/jira/client.go                 Jira REST client (CreateIssue/GetIssueStatus/
                                              GetTransitions/DoTransition/AddComment/TransitionToStatus/ListProjects)
internal/infra/jira/resolver.go               IntegrationClientResolver: ClientResolver + MappingResolver + adapter
internal/infra/jira/asset_route_resolver.go   AssetRouteResolver: asset scope/criticality for routing rules
internal/infra/jobs/jira_sync_tasks.go        asynq task + handler for outbound status sync
internal/infra/http/handler/jira_webhook_handler.go   create-ticket + inbound webhook
internal/app/finding/vulnerability_service.go  UpdateFindingStatus → enqueue outbound sync (SetJiraStatusSyncHook)
cmd/server/{services,workers,main}.go          wiring (resolvers, worker handler, enqueue hook)
```
