# #350 — Git-Host Connector (GitHub / GitLab / Bitbucket)

- **Q/WS**: Q3 / WS-A
- **Status**: Pending — blocked on sandbox PAT for each host + scope decision
- **Seam**: `internal/app/connector/connector.go`
- **Related**: #345 Recon adapter parser (completed — this connector **discovers** repos; scanning their secrets is the recon adapter's job, keep them separate)

## 1. Scope

**Ships:**
- `internal/app/connector/githost/` implementing `connector.Connector`.
- Three sub-adapters: `github/`, `gitlab/`, `bitbucket/` selected by `Credentials.APIURL` host, each behind the same `Connector` facade.
- Enumerates: Repositories (public + private accessible to token), Organizations / Groups / Workspaces, Branches (default only in v1), Collaborators count, Webhooks, Deploy keys.
- Rate-limit aware with token-bucket per-host.
- Integration test per host (skipped unless that host's sandbox env var is set).

**Does NOT ship:**
- Commit / tree traversal — `git clone` + parse is a separate recon adapter task.
- Secret scanning — part of the recon pipeline.
- Issue / PR enumeration — separate "project-management" feature if product wants it.
- SAML / SCIM user provisioning reflection.

## 2. External dependencies

Per host:

| Host | Library | Install |
|---|---|---|
| GitHub (cloud + Enterprise Server) | `github.com/google/go-github/v61/github` | `go get github.com/google/go-github/v61` |
| GitLab (SaaS + self-managed) | `github.com/xanzy/go-gitlab` | `go get github.com/xanzy/go-gitlab` |
| Bitbucket Cloud | `github.com/ktrysmt/go-bitbucket` | `go get github.com/ktrysmt/go-bitbucket` |
| Bitbucket Server / Data Center | custom HTTP (no maintained Go lib) | own client in `bitbucket/server_client.go` |

**Note:** Bitbucket Cloud and Bitbucket Server have different APIs — treat as two sub-adapters (`bitbucket_cloud` and `bitbucket_server`), distinguished by `Credentials.APIURL` (`api.bitbucket.org` vs self-hosted).

Sandbox credentials needed (per host, scope = **read-only**):
- **GitHub**: fine-grained PAT, scopes `metadata:read`, `contents:read`, `administration:read` (for webhooks/keys), optionally `organization_administration:read` for org-level discovery.
- **GitLab**: PAT with scope `read_api`.
- **Bitbucket Cloud**: App password with `repositories:read`, `workspace_membership:read`.
- **Bitbucket Server**: HTTP access token with `Repository read`.

## 3. Data model

### 3.1 Credentials

Re-uses `connector.Credentials`:
```go
Token  string // PAT / app password (decrypted by caller)
APIURL string // https://api.github.com | https://gitlab.example.com/api/v4 | etc.
```

Plus one additional field the current struct does NOT have yet — **add this** when landing:
```go
// OrgScope is the org/group/workspace to enumerate. Empty = "everything the token can see".
// Required for Bitbucket Cloud (workspace), optional for GitHub/GitLab.
OrgScope string
```

### 3.2 Per-asset properties

Repositories:
```json
{
  "git_host": "github",
  "git_host_url": "https://github.com",
  "git_repo_full_name": "acme/api",
  "git_repo_id": "123456789",
  "git_visibility": "private",
  "git_default_branch": "main",
  "git_archived": false,
  "git_fork": false,
  "git_size_kb": 12345,
  "git_pushed_at": "2026-04-18T10:00:00Z",
  "git_webhook_count": 3,
  "git_deploy_key_count": 1,
  "git_collaborator_count": 8
}
```

Organizations / Groups / Workspaces → `TypeOrganization` with `git_members_count`, `git_two_factor_required`, `git_public_repos`, etc.

## 4. Public interface

```go
// internal/app/connector/githost/githost.go
package githost

type Connector struct {
    subs map[Host]subConnector // github, gitlab, bitbucket_cloud, bitbucket_server
}

type Host string
const (
    HostGitHub          Host = "github"
    HostGitLab          Host = "gitlab"
    HostBitbucketCloud  Host = "bitbucket_cloud"
    HostBitbucketServer Host = "bitbucket_server"
)

type subConnector interface {
    validate(ctx context.Context, creds connector.Credentials) error
    discover(ctx context.Context, tenantID shared.ID, creds connector.Credentials) ([]connector.DiscoveredAsset, error)
}

func New() *Connector

func (c *Connector) Provider() connector.Provider // "git-host"
func (c *Connector) Validate(ctx context.Context, creds connector.Credentials) error
func (c *Connector) Discover(ctx context.Context, tenantID shared.ID, creds connector.Credentials) (*connector.DiscoveryResult, error)
```

### 4.1 Host detection from APIURL

```go
// detectHost returns the sub-connector key for a given APIURL.
// Ambiguous URLs (e.g. self-hosted Gitea that masquerades as GitHub) return
// ErrUnknownHost — operator must set a "git_host_type" hint on the integration.
func detectHost(apiURL string) (Host, error)
```

Rules:
- `api.github.com` → `github`.
- `gitlab.com` or path contains `/api/v4` → `gitlab`.
- `api.bitbucket.org` → `bitbucket_cloud`.
- `bitbucket.<...>/rest/api/1.0` → `bitbucket_server`.
- Self-hosted GHE (`ghe.example.com`) → user must set integration metadata `git_host_type=github`.

## 5. Resource mapping

| Git-host resource | Internal `AssetType` | ExternalID |
|---|---|---|
| Repository | `TypeCodeRepository` | `repo/<host>/<full_name>` |
| Organization (GH) / Group (GL) / Workspace (BB) | `TypeOrganization` | `org/<host>/<slug>` |
| Webhook on repo | `TypeIntegration` | `hook/<host>/<repo_id>/<hook_id>` |
| Deploy key on repo | `TypeCredential` | `depkey/<host>/<repo_id>/<key_id>` |

**No asset type for branches** — branches are properties on the repo, not standalone assets.

## 6. Rate limiting

Each host enforces its own limits:
- GitHub: 5000/hr authenticated, **use Conditional Requests (ETag)** to avoid consuming budget for unchanged resources.
- GitLab: 2000/min by default, configurable on self-managed.
- Bitbucket Cloud: 1000/hr for most endpoints.

Implementation: shared `pkg/rate/hostbucket` (create as a tiny utility — token bucket keyed on `host+token_hash`). Each sub-adapter acquires a token before every request. Respect `X-RateLimit-Remaining` and `Retry-After`.

Discover MUST NOT burn a tenant's entire hourly budget in one run — hard cap `max_requests_per_run` (default 2000, configurable via integration metadata).

## 7. Test plan

### 7.1 Unit
- `TestDetectHost_*` — one test per URL pattern above + one for ambiguous → error.
- `TestValidate_EachHost_TokenRejected_WhenAuthFails` — fake HTTP 401.
- `TestDiscover_EachHost_MapsRepo`.
- `TestDiscover_Pagination_MultiplePages` — per host, since each has a different pagination scheme (GH: Link header, GL: X-Next-Page, BB: `next` field in body).
- `TestDiscover_RateLimit_Pauses` — fake returns 429 with `Retry-After: 2` → assert wait.
- `TestDiscover_RequestBudget_Capped` — set budget=5, fake returns many repos → assert enumeration stops at 5 and partial result returned with budget-exceeded error.
- `TestDiscover_ETag_ReducesCalls` (GitHub only) — second run reuses cached ETag, assert 304s don't eat rate budget.
- `TestDiscover_ArchivedFilter` — `include_archived=false` metadata → archived repos skipped.

### 7.2 Integration
Build tag `integration_githost`. Per host sandbox env: `GH_TEST_PAT`, `GL_TEST_PAT`, `BB_CLOUD_USER` + `BB_CLOUD_APP_PASSWORD`, `BB_SERVER_URL` + `BB_SERVER_PAT`. Each test creates a fixture repo, runs Discover, asserts, deletes fixture.

CI runs integration tests on a weekly schedule, not per-PR (cost + noise).

## 8. Rollout

1. Land sub-adapters one at a time: GitHub first (largest user base), then GitLab, then Bitbucket Cloud, then Bitbucket Server. Each behind its own sub-flag: `connectors.githost.<host>.enabled`.
2. Release notes must call out:
   - Required token scopes.
   - ETag behaviour (GitHub) — cached between runs in `integration.state_cache`.
   - Request budget knob.
3. The `POST /integrations/test` button in the UI calls `Validate` only, not `Discover` — rate-limit friendly.

## 9. Open questions

| # | Question | Who answers | Default |
|---|---|---|---|
| Q1 | Add `OrgScope` to `Credentials`? (yes — Bitbucket Cloud needs it; GitHub/GitLab optional) | Platform | Yes, add |
| Q2 | Discover user-owned repos too, or org-only? | Security | Org-only by default (user-owned repos usually personal/noisy). Flag per-integration. |
| Q3 | Include forks? | Product | No by default (noise); flag per-integration |
| Q4 | Store webhook URLs (may contain secrets in query)? | Security | Store URL **with query string redacted**; never store webhook secrets |
| Q5 | Parse `CODEOWNERS` for asset-to-team linking? | Product | Not v1 — follow-up |
| Q6 | Gitea / Gerrit / AWS CodeCommit support? | Product | No — v2+ |

## 10. Non-goals

- Cloning / file-tree traversal (that's the recon adapter path).
- Issue/PR/review enumeration.
- CI run history (GitHub Actions, GitLab CI) — separate task, different domain.
- Secret scanning — recon pipeline.
- License scanning — SCA task.
