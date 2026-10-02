# Remediation Campaign → Jira Epic

> Turn a remediation campaign into a tracked **Jira epic** — the "create a task
> that syncs to Jira" half of the Mobilization story (RFC-006 Phase 3e
> `WorkItem` seam). Completes Tier-1 #2 alongside campaign progress tracking.

## Endpoint

```
POST /api/v1/remediation/campaigns/{id}/create-ticket   (permission: remediation:write)
Body: { "project_key": "SEC" }
```

Creates a Jira **epic** for the campaign in the given project and links it.
Response:

```jsonc
{
  "campaign_id": "…",
  "provider": "jira",
  "issue_key": "SEC-42",
  "issue_url": "https://org.atlassian.net/browse/SEC-42",
  "already_existed": false   // true if the campaign was already linked (idempotent)
}
```

The epic body is rendered from the campaign: description + progress
(`resolved/total`, percentage) + due date. Labels: `openctem`,
`remediation-campaign`.

## Design

The campaign service **owns the orchestration** (idempotency + link
persistence); the jira package stays campaign-agnostic and only knows "create an
epic for this tenant".

```
RemediationCampaignService.CreateTicket
  ├─ load campaign (tenant-scoped)                    [remediation repo]
  ├─ existing link for (campaign, "jira")?  → return it, already_existed=true
  ├─ epicCreator.CreateEpic(tenant, project, …)       [jira.SyncService]
  │     └─ resolve per-tenant Jira client → CreateIssue(IssueType="Epic")
  └─ persist remediation_campaign_tickets row         [campaign-ticket repo]
```

- **Decoupling**: the campaign service depends on jira only through the narrow
  `CampaignEpicCreator` interface (primitive params), so the `exposure` package
  imports nothing from `jira`. `*jira.SyncService.CreateEpic` satisfies it.
- **Idempotency**: the unique `(tenant_id, campaign_id, provider)` link row plus
  the pre-create lookup mean re-POSTing returns the existing epic rather than
  opening a duplicate.
- **Tenant isolation + creds**: `CreateEpic` resolves the per-tenant Jira client
  via the same `ClientResolver` as finding ticketing; secrets are
  redacted from the epic summary/description defensively.
- **Degrades off**: with no ticketing wired (no Jira integration), `CreateTicket`
  returns `ErrTicketingNotConfigured` (HTTP 400) — the rest of the campaign
  service is unaffected.

## Storage

`remediation_campaign_tickets` (migration `000177`) — a side table, not columns
on `remediation_campaigns`, so the campaign aggregate stays stable and more
providers/issues can compose later:

| column | note |
|--------|------|
| `tenant_id`, `campaign_id` | FK, `ON DELETE CASCADE` |
| `provider` | `jira` (default) |
| `issue_key`, `issue_url` | the epic |
| unique `(tenant_id, campaign_id, provider)` | one ticket per provider |

## Layering

| Layer | File |
|-------|------|
| Domain | `pkg/domain/remediation/campaign_ticket.go` |
| Repo | `internal/infra/postgres/remediation_campaign_ticket_repository.go` |
| Service | `internal/app/exposure/remediation_campaign.go` (`CreateTicket`) |
| Jira | `internal/app/jira/sync_service.go` (`CreateEpic`) |
| Handler/route | `remediation_campaign_handler.go`, `routes/remediation.go` |

## Outbound status sync (campaign → epic)

When a campaign reaches `completed` — whether by an explicit status change, the
manual progress `refresh`, or the background reconcile auto-complete — its
linked epic is transitioned to **Done** (best-effort):

- `RemediationCampaignService.syncEpicOnCompletion` looks up the campaign's Jira
  link and calls `CampaignEpicCreator.TransitionEpic`.
- `jira.SyncService.TransitionEpic` is echo-guarded (skips if the epic is
  already at the target) and falls back to a **comment** when the workflow
  offers no transition — the same pattern as finding-level outbound sync.
- Errors are logged, never propagated: a Jira hiccup must not fail campaign
  completion. The echo-guard makes it safe to fire from every completion path.

Target status is `Done` (Jira's default done state); a per-tenant override is a
follow-up.

## Inbound status sync (epic → campaign)

The reverse direction, mirroring finding-level inbound sync. A Jira webhook that
moves a campaign's linked epic to a done state (`Done`/`Resolved`/`Closed`/
`Complete`/`Completed`) marks the campaign **completed**.

- `HandleJiraWebhook` calls `CampaignEpicSink.HandleEpicStatusChange` (best-
  effort, independent of the finding path — an issue is either a finding ticket
  or a campaign epic, and each sink no-ops on a key that isn't its own).
- `RemediationCampaignService.HandleEpicStatusChange`: done-status guard →
  `CampaignTicketRepository.GetByIssueKey` (reverse lookup) → load campaign →
  `Complete()`. A draft/paused (non-completable) campaign is logged and skipped.
- **Loop-safe**: it persists via `repo.Update` directly (not
  `UpdateCampaignStatus`), so it does **not** re-fire the outbound transition;
  and an already-terminal campaign is a clean no-op. So the
  completion→epic-Done→webhook→inbound cycle converges immediately.

Together with the outbound path, **campaign↔epic sync is now bidirectional** —
matching the finding↔ticket sync.

## Planned follow-ups

- **Per-tenant epic done-status mapping** (instead of the fixed `Done`).
- **Richer inbound mapping** (e.g. epic In Progress → campaign active).
- **GitHub Issues** as a second provider via the same `CampaignEpicCreator` seam.
