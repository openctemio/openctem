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
- **Shared secret redaction.** Jira and GitHub route ticket text through one
  implementation, `safetext.RedactSecrets` (`pkg/safetext/redact.go`), so they
  cannot diverge. It removes whole private key blocks (header, base64 body and
  footer, also when the footer is cut off), JWTs, AWS access key ids
  (`AKIA`/`ASIA`/...), GitHub, Slack and Google tokens, `Authorization`/`Bearer`
  values and `password=`/`api_key:`-style assignments. The mobilization brief
  and the campaign epic description are written by people, but they get the
  same redaction, a length cap (`safetext.MaxBriefRunes`) and the same block
  encoding as finding text, so they cannot add links or mentions either. Secret
  findings additionally **omit the raw description and the masked preview**
  and surface only the location plus a pointer to the platform. Pentest,
  TLP and data-exposure rules come from the shared outbound gate
  (`ticketing-integration.md`, "Outbound gate"): the generic and workflow
  routes refuse pentest findings, and status pushes stop for a campaign above
  the organization's tracker TLP limit.
- **Output encoding** (RFC-040 §5.4). Finding text is attacker-influenced, and
  the issue body is GitHub-flavored markdown. After redaction:
  - One-line values (location) go into a code span
    (`safetext.MarkdownInline`).
  - The description goes into a fenced code block (`safetext.MarkdownBlock`).
  - Each fence is longer than any backtick run in the text, so the text cannot
    close it.
  - Inside code GitHub renders no links, images, HTML, `@mentions` or
    `#refs`, so scanner text cannot ping a team or close an issue.
  - The title is plain text: one line, cleaned of control, bidi and
    zero-width characters, at most 240 characters.
- **Idempotent.** If the finding's `work_item_uris` already contains an issue
  URL for the requested `owner/repo`, the existing link is returned and no new
  issue is created.
- **Duplicate-proof create.** The issue body ends with a hidden marker
  `<!-- openctem:k=finding;o=<finding id>;t=<tenant tag> -->` (the tenant tag
  is a hash, so the tenant id is not written into the repository). Before
  creating, the service lists the repository's 100 newest `openctem` issues
  (the issue list, not the search index, so an issue created a moment ago is
  in it) and adopts the oldest one whose body **ends** with exactly this
  marker. A create whose response was lost, or whose URL was not recorded, is
  therefore recovered by the next attempt instead of opening a second issue.
  A marker of another finding or tenant, or one quoted inside finding text,
  never matches; if the list cannot be read the create is refused.
- **Best-effort link persistence.** Once the issue is created, its URL is added
  to the finding's `work_item_uris`. A persistence failure is logged but does
  not fail the request (the issue already exists; the next attempt adopts it).
- **Labels.** Issues are tagged `openctem`, `security`, and the finding
  severity.

## Layering

| Layer        | Component                                                        | Responsibility                                  |
|--------------|-----------------------------------------------------------------|-------------------------------------------------|
| HTTP handler | `internal/infra/http/handler/jira_webhook_handler.go`           | Parse request, select provider, map errors      |
| App service  | `internal/app/ticketing/github_ticket.go` (`GitHubTicketService`) | Resolve integration, idempotency, build body    |
| Shared       | `pkg/safetext/redact.go` (`RedactSecrets`)                      | Provider-agnostic secret scrubbing              |
| Shared       | `pkg/safetext` (`MarkdownInline`, `MarkdownBlock`, `Jira*`)      | Output encoding per ticket format (RFC-040)     |
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
