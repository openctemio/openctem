# Ticketing Integration (Jira) — Mobilization

> **Status**: Outbound + inbound functional (per-tenant). Provider abstraction &
> configurable mapping are designed in [RFC-006](../rfcs/RFC-006-ticketing-provider-and-mapping.md).
> Ticketing is the CTEM **Mobilization** pillar.

## Overview

OpenCTEM links findings to external tickets and keeps status in sync:

- **Create** a Jira ticket from a finding (`POST /api/v1/findings/{id}/create-ticket`).
- **Link / unlink** an existing ticket to a finding.
- **Inbound webhook** (`POST /api/v1/webhooks/incoming/jira?tenant=<id>`): a Jira
  status change updates the finding status (and can trigger a verification scan).

A finding ↔ ticket link is stored as a URL in `finding.WorkItemURIs()`.

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
   Enter base URL, the Atlassian account email, and the API token. Optionally a
   project key.
3. Create a ticket from any finding via the finding actions, or the
   `create-ticket` endpoint with `{"project_key": "SEC", "issue_type": "Bug"}`.
4. (Inbound) Configure a Jira webhook to
   `POST /api/v1/webhooks/incoming/jira?tenant=<tenant-id>` (HMAC via
   `JiraSecret`, fail-closed).

## Safety properties (shipped)

- **Idempotent create** (#134): a finding already ticketed in the target project
  (its `WorkItemURIs` contains `/browse/<PROJECT>-`) is not re-created.
- **Secret redaction** (#135): secret-leak findings never copy the raw value into
  a ticket; descriptions are run through redaction patterns as defense-in-depth.

## Current mappings (hardcoded — RFC-006 makes these configurable)

| Direction | Mapping | Where |
|-----------|---------|-------|
| Finding severity → Jira priority | critical→Highest, high→High, medium→Medium, low→Low | `mapSeverityToJiraPriority` |
| Jira status → finding status (inbound) | done/resolved/closed→fix_applied; in progress/in review→in_progress; to do/backlog/reopened→confirmed | `mapJiraStatusToFinding` |

Customers with non-default Jira workflows are silently dropped today. The
`MappingConfig` type (`internal/app/jira/mapping.go`, shipped) makes these
configurable per integration: `DefaultMappingConfig()` reproduces the table
above, and `ParseMappingConfig(integration.Config())` overlays overrides from
`config.ticketing` (severity→priority, inbound status map, default priority,
issue type) — partial configs only change what they specify; invalid status
targets are skipped. The hardcoded functions now delegate to the default
mapping (zero behaviour change). **Phase 2** wires `ParseMappingConfig` into the
create + inbound-webhook paths (per-tenant), so a tenant's overrides take effect.

Example `config.ticketing` override:

```json
{ "ticketing": {
    "issue_type": "Task",
    "default_priority": "P3",
    "severity_to_priority": { "critical": "P1", "high": "P2" },
    "status_inbound": { "Shipped": "fix_applied", "QA": "in_progress" }
}}
```

## Roadmap (RFC-006)

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Per-tenant client resolver | **Done** (#137, ui#152) |
| 1 | `MappingConfig` type + defaults (zero behaviour change) | **Done** (mapping.go) |
| 2 | Wire `ParseMappingConfig` into create + inbound webhook (per-tenant) + `TicketProvider` interface | Planned |
| 3 | Outbound status sync via outbox/worker + echo-guard | Planned |
| 4 | 2nd provider (ServiceNow/GitHub) + typed `finding_tickets` + UI | Planned |

Related future work (no RFC yet): **Jira Assets / JSM CMDB** — pull asset
business-context to enrich prioritisation, push discovered assets, link CI
objects to finding tickets. Today only the core issue API is used.

## Key files

```
internal/app/jira/sync_service.go             SyncService, resolveClient, redaction
internal/app/jira/mapping.go                   MappingConfig (defaults + per-integration overrides)
internal/infra/jira/client.go                 Jira REST client (CreateIssue/GetIssueStatus/TestConnection)
internal/infra/jira/resolver.go               IntegrationClientResolver + app-interface adapter
internal/infra/http/handler/jira_webhook_handler.go   create-ticket + inbound webhook
cmd/server/services.go                         wiring (repos.Integration + Encryptor)
```
