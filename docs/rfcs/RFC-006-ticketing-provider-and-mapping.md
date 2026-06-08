# RFC-006: Ticketing — Provider Abstraction + Configurable Mapping

- **Status**: Proposed
- **Created**: 2026-06-04
- **Owner**: Platform / Mobilization
- **Problem**: The Jira integration hardcodes status/severity mappings to one vendor's default workflow, only syncs status *inbound* (Jira→finding), and is Jira-only. Real customers run customized Jira workflows (different status names/transitions), want findings to push status *outbound*, and some use ServiceNow / GitHub Issues / GitLab. Ticketing is the CTEM **Mobilization** pillar; it needs to be configurable and provider-agnostic.

---

## 1. Current state (grounded)

Code today (`internal/app/jira/sync_service.go`, `internal/infra/jira/client.go`):

- **Inbound only**: `HandleJiraWebhook` maps a Jira status → finding status and updates the finding. There is **no outbound** "finding status changed → transition the Jira issue" — `jira.Client` exposes only `CreateIssue`, `GetIssueStatus`, `TestConnection` (no `Transition`, no `AddComment`).
- **Hardcoded mappings**:
  - `mapJiraStatusToFinding` — fixed English status names (`"in progress"`, `"done"`, `"resolved"`, …). A customer whose workflow uses `"In Dev"`, `"QA"`, `"Shipped"` gets silently dropped (logged debug, no sync).
  - `mapSeverityToJiraPriority` — fixed `critical→Highest`, etc. Many Jira projects rename priorities or don't use them.
- **Jira-only**: the service, client, and webhook are Jira-specific. No abstraction for ServiceNow / GitHub Issues / GitLab.
- **Links**: a finding ↔ ticket link is a URL in `finding.WorkItemURIs()` (generic list), not a typed link with provider/issue-key/project.
- **Already shipped (this milestone)**: idempotent create (one ticket per finding+project, #134) and secret redaction in descriptions (#135). Config storage already exists per-integration: `Integration.Config() map[string]any` (JSONB) + `Metadata()`.

> **⚠ Blocking finding (2026-06-04): outbound ticket creation is currently non-functional.** `cmd/server/services.go` builds the sync service as `jira.NewSyncService(repos.Finding, nil, log)` — the Jira client is **nil**, and `jira.NewClient` is **never called anywhere** in `internal/`/`cmd/`. So `CreateTicketFromFinding` always returns `"Jira integration not configured"` and `POST /findings/{id}/create-ticket` is effectively dead. Only the **inbound** webhook works (it needs no client — it just updates the finding). **Per-tenant client resolution is the real Phase 0** and a prerequisite for everything below; until it exists, configurable mapping/outbound have nothing to run against. Mirror the per-tenant SMTP resolver (`TenantSMTPResolver`/`IntegrationSMTPResolver`): resolve the tenant's active integration, decrypt its credentials (AES-256-GCM, `APP_ENCRYPTION_KEY`), and build a client on demand.

## 2. Goals / Non-goals

**Goals**
1. **Configurable mapping per integration** — status (both directions), severity→priority, issue type, labels, and project routing, with safe defaults that preserve today's behaviour.
2. **Outbound status sync** — when a finding transitions (e.g. resolved / false-positive / accepted), transition or comment the linked ticket. Closes the second half of bidirectional sync.
3. **Provider abstraction** — a `TicketProvider` interface so Jira is one implementation; ServiceNow / GitHub Issues / GitLab can follow without touching callers.
4. **No echo loops** and **no duplicate work** under bulk/concurrent operation.

**Non-goals**
- Building the ServiceNow/GitHub providers now (just the seam + Jira conforming to it).
- A visual mapping editor (config is JSON in the integration record first; UI later).
- Replacing `WorkItemURIs` wholesale (we layer typed links additively).

## 3. Proposed design

### 3.1 TicketProvider interface

```go
type TicketProvider interface {
    CreateIssue(ctx, CreateIssueInput) (*IssueRef, error)
    Transition(ctx, issueKey string, toStatus string) error   // NEW — outbound status
    AddComment(ctx, issueKey, body string) error               // NEW — sync notes/echo-free updates
    GetStatus(ctx, issueKey string) (string, error)
    TestConnection(ctx) error
    Kind() string // "jira" | "servicenow" | "github" | ...
}
```

The current Jira `Client` becomes the `jira` implementation (add `Transition`/`AddComment` via the Jira REST `transitions` + `comment` endpoints). `SyncService` depends on `TicketProvider`, resolved per tenant/integration from a small factory.

### 3.2 Configurable mapping (stored in `Integration.Config`)

No migration — reuse the existing JSONB `config`:

```jsonc
{
  "ticketing": {
    "project_key": "SEC",
    "issue_type": "Bug",
    "labels": ["openctem", "security"],
    "severity_to_priority": { "critical": "Highest", "high": "High", "medium": "Medium", "low": "Low" },
    "status_inbound":  { "Done": "fix_applied", "QA": "in_progress", "Shipped": "fix_applied" },
    "status_outbound": { "resolved": "Done", "false_positive": "Won't Do", "accepted": "Acknowledged" },
    "routing": [ { "match": { "asset_group": "payments" }, "project_key": "PAY" } ]
  }
}
```

- A typed `MappingConfig` loads from `config.ticketing`, **falling back to the current hardcoded maps** when absent → zero behaviour change for existing tenants.
- `status_inbound` is case-insensitive and overrides/extends the built-in defaults.
- `routing` chooses `project_key`/assignee by asset group / business unit / severity (the "routing gaps" edge-case from the deep-dive).

### 3.3 Outbound status sync

When a finding transitions to a terminal/notable state and has a linked ticket, look up `status_outbound[newFindingStatus]` and call `provider.Transition(issueKey, target)`; if the transition isn't allowed (workflow), fall back to `AddComment` with the status change. Triggered from the finding status-change path (workflow action or a domain event), **not** inline in the request — enqueued (see 3.5).

### 3.4 Echo-guard

Inbound webhook updates a finding → that finding change must **not** re-trigger an outbound push back to the same ticket. Tag the inbound-originated update (e.g. an `origin=jira_webhook` marker on the status-change event, or a short-lived per-(finding,issue) suppression) so the outbound trigger skips it. Without this, Jira webhook → finding update → outbound transition → Jira webhook → … loops.

### 3.5 Reliability: reuse the async worker

Outbound create/transition/comment are third-party calls subject to rate limits and transient failures. Route them through the **transactional-outbox + bounded worker** pattern already built for async ingest (RFC-005): record intent in the same tx as the finding change, a worker performs the API call with retries/backoff + dead-letter, and per-tenant fair-queuing prevents one tenant's bulk operation from starving others. This also gives idempotency keys for free.

### 3.6 Typed ticket links (additive)

Keep `WorkItemURIs` for back-compat; optionally add a `finding_tickets` association (finding_id, provider, project_key, issue_key, url, created_at) so lookups (webhook → finding, dedup, outbound) are precise instead of URL substring matching (which #134 uses today). Optional in phase 1; the URL heuristic works meanwhile.

## 4. Backward compatibility & rollout

0. **Phase 0 (prerequisite — makes outbound actually work)** — per-tenant Jira **client resolution**: a resolver that loads the tenant's active Jira integration, decrypts its credentials, and builds a `jira.Client` on demand (mirrors `IntegrationSMTPResolver`). Without this, every outbound path is a no-op. Wire it into `SyncService` (resolve per call) so `CreateTicketFromFinding` works.
1. **Phase 1** — `TicketProvider` interface; Jira `Client` conforms (add `Transition`/`AddComment`). `MappingConfig` loader with defaults = today's hardcoded maps. No behaviour change.
2. **Phase 2** — wire configurable mapping into create + inbound webhook (read `config.ticketing`, fall back to defaults).
3. **Phase 3** — outbound status sync via the async worker + echo-guard, behind a per-integration flag (default off). **Detailed design: [RFC-006 Phase 3 — Bidirectional Jira Status Sync](./RFC-006-phase-3-bidirectional-sync.md)** (echo-guard, `ticket_links` table, outbound mapping, conflict policy, and a `WorkItem` seam so the same engine later serves a grouping `remediation_task`).
4. **Phase 4** — second provider (GitHub Issues or ServiceNow) to validate the abstraction; optional typed `finding_tickets` table + mapping UI.

## 5. Alternatives considered

- **Keep Jira-only, just make maps configurable** — solves the workflow-divergence pain with less work, but locks out ServiceNow/GitHub and leaves outbound sync unbuilt. The interface is cheap; do it.
- **Generic webhook/automation rules instead of a provider interface** — more flexible but pushes mapping complexity onto users; a typed provider + config is more usable for the common case.
- **External iPaaS (Workato/Tray)** — out of scope; the platform should own first-class ticketing.

## 6. Open questions

- Outbound trigger source: a finding domain event vs the existing workflow "create ticket" action path — prefer a single status-change event consumers subscribe to.
- Transition resolution: Jira transitions are by *transition id*, not target status name; need a per-project transition lookup/cache (`GET /issue/{key}/transitions`).
- Comment-sync scope (do we mirror platform comments ↔ Jira comments?) — defer; risk of noise + echo.
- Multiple linked tickets per finding (multi-project) — outbound should target all, or a designated primary?
