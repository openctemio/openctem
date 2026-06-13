# GitHub Issues Ticketing

OpenCTEM can create a GitHub issue from a finding and link it back, alongside
the existing Jira integration. This is **create-from-finding + link only** —
there is no inbound status sync yet (see [Follow-ups](#follow-ups)).

## Endpoint

The provider is selected on the existing create-ticket endpoint via a
`provider` field (default `jira`):

```
POST /api/v1/findings/{id}/create-ticket
Content-Type: application/json

{
  "provider": "github",
  "owner": "my-org",
  "repo": "my-service"
}
```

| Field      | Required (github) | Notes                                   |
|------------|-------------------|-----------------------------------------|
| `provider` | no                | `"jira"` (default) or `"github"`        |
| `owner`    | yes               | GitHub org/user that owns the repo      |
| `repo`     | yes               | Repository name                         |

Omitting `provider` (or sending `"jira"`) keeps the previous Jira behaviour
unchanged (uses `project_key` / `issue_type`).

**Response** (`201 Created`) — identical shape for both providers:

```json
{
  "finding_id": "…",
  "ticket_key": "#42",
  "ticket_url": "https://github.com/my-org/my-service/issues/42",
  "linked_at": "2026-06-13T10:00:00Z"
}
```

`ticket_key` is `#<issue-number>` for GitHub, the Jira issue key for Jira.

### Error mapping

| Condition                                              | HTTP |
|--------------------------------------------------------|------|
| missing `owner`/`repo`, invalid id, bad credentials    | 400  |
| no connected GitHub integration for the tenant         | 400  |
| `provider=github` but GitHub ticketing not wired       | 400  |
| finding not found                                      | 404  |
| GitHub API / internal error                            | 500  |

## Design

Parallel to Jira, intentionally:

- **Credential resolution is tenant-isolated.** The service lists the tenant's
  GitHub integrations via `integrationRepo.ListByProvider(ctx, tenantID,
  ProviderGitHub)`, picks the first `StatusConnected` one, and decrypts its
  stored credential exactly as the SCM layer does
  (`IntegrationService.decryptCredentials`): `CredentialsEncrypted()` →
  `encryptor.DecryptString`, with plaintext fallback on decryption failure.
  Credentials are never read from the request.
- **Shared secret redaction.** Both providers route ticket text through one
  implementation, `ticketing.RedactSecrets`, so they cannot diverge. Secret
  findings additionally **omit the raw description entirely** and surface only
  the masked value plus a pointer to the platform — the credential is never
  written into a third-party tracker.
- **Idempotent.** If the finding's `work_item_uris` already contains an issue
  URL for the requested `owner/repo`, the existing link is returned and no new
  issue is created.
- **Best-effort link persistence.** Once the issue is created, its URL is added
  to the finding's `work_item_uris`. A persistence failure is logged but does
  not fail the request (the issue already exists; re-running is idempotent).
- **Labels.** Issues are tagged `openctem`, `security`, and the finding
  severity.

## Layering

| Layer        | Component                                                        | Responsibility                                  |
|--------------|-----------------------------------------------------------------|-------------------------------------------------|
| HTTP handler | `internal/infra/http/handler/jira_webhook_handler.go`           | Parse request, select provider, map errors      |
| App service  | `internal/app/ticketing/github_ticket.go` (`GitHubTicketService`) | Resolve integration, idempotency, build body    |
| Shared       | `internal/app/ticketing/redact.go` (`RedactSecrets`)            | Provider-agnostic secret scrubbing              |
| SCM client   | `internal/infra/scm/github.go` (`GitHubClient.CreateIssue`)     | `POST /repos/{owner}/{repo}/issues`             |
| Domain       | `pkg/domain/vulnerability`, `pkg/domain/integration`            | Finding + integration entities/repositories     |

The service depends on a small `issueCreator` interface (one `CreateIssue`
method) rather than the concrete SCM client, which keeps it unit-testable
without network access; `*scm.GitHubClient` satisfies it in production.

## Follow-ups

- Inbound status sync (GitHub webhook → finding status), mirroring the Jira
  `IncomingJiraWebhook` path.
- A provider-abstraction interface so Jira/GitHub share one orchestration
  service instead of two.
