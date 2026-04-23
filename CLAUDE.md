# API Project - Claude AI Assistant Guidelines

> Essential coding standards and patterns for the OpenCTEM API (Go backend).

## Project Context

OpenCTEM Platform monorepo: `api/` (this), `ui/` (Next.js), `agent/` (Go), `sdk-go/`, `docs/` (GitHub Pages).

- **Local docs**: `./docs/` — API-specific documentation (architecture, development guides)
- **Global docs**: `../docs/` — Workspace-level GitHub Pages docs

---

## Test-Driven Development (TDD)

**CRITICAL:** For any new feature or significant change:

1. **Research** — Analyze requirements, identify all use cases and edge cases
2. **Write tests FIRST** — Must fail initially. Cover all edge cases. Follow existing patterns in `tests/`
3. **Implement** — Make tests pass, then refactor. Do not skip failing tests.

**Test locations:** `tests/unit/`, `tests/integration/`, `tests/repository/`

```bash
make test                                    # All tests
go test -v ./tests/integration/...           # Integration tests
go test -cover ./...                         # With coverage
```

---

## Tech Stack & Structure

- **Go 1.26+**, strict linting via golangci-lint
- **PostgreSQL** persistence, **Chi Router**, **DDD architecture**

```
api/
├── cmd/                    # Application entrypoints
├── internal/
│   ├── app/               # Application services (business logic)
│   │   ├── <cluster>/     # One bounded context per folder (audit/,
│   │   │                  # asset/, finding/, auth/, tenant/, ...)
│   │   └── <cluster>_service.go  # Compat shim — type aliases re-
│   │                      #   exporting the cluster's public surface
│   │                      #   as `app.X` for pre-refactor callers.
│   │                      #   New code should import the cluster
│   │                      #   package directly.
│   ├── domain/            # Domain models and interfaces
│   │   └── shared/        # Shared types (ID, errors)
│   └── infra/             # Infrastructure layer
│       ├── http/          # Handlers, routes, middleware
│       ├── postgres/      # Database repositories
│       ├── redis/         # Cache client
│       ├── notification/  # Multi-channel notification clients
│       └── controller/    # Background job controllers
├── pkg/                   # Public packages (domain models, utils)
├── migrations/            # Database migrations
├── tests/                 # Test suites
└── docs/                  # Local documentation
```

---

## MANDATORY: Code Quality Checks

**Run before every commit:**

```bash
# 1. Run linter - MUST pass with no errors
GOWORK=off golangci-lint run ./...

# 2. Format code
goimports -w ./...

# 3. Run tests (if applicable)
make test
```

**Pre-commit hooks will fail if linting errors exist.**

---

## Linting Rules & Common Issues

### 1. Error Comparison (errorlint)

**Always use `errors.Is()` instead of `==` for error comparison.**

```go
// BAD
if err == sql.ErrNoRows { return ErrNotFound }

// GOOD
if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }
```

### 2. Pre-allocate Slices (prealloc)

```go
// BAD
var items []Item
for _, id := range ids { items = append(items, getItem(id)) }

// GOOD
items := make([]Item, 0, len(ids))
for _, id := range ids { items = append(items, getItem(id)) }
```

### 3. Use Constants (goconst)

Use constants for repeated string literals. Common constants in `internal/infra/postgres/constants.go`.

### 4. Check Error Returns (errcheck)

```go
// BAD
defer tx.Rollback()

// GOOD
defer func() { _ = tx.Rollback() }()
```

### 5. File Formatting (goimports)

Run `goimports -w ./...` before committing. Use tabs for indentation.

### 6. Integer Overflow (gosec)

Add bounds checking when converting between integer types (`math.MaxInt32` before `int32(v)`).

### 7. Cyclomatic Complexity (cyclop)

Keep functions under 30 complexity. Use `//nolint:cyclop` for route registration.

### 8. File Naming Inside `internal/app/<cluster>/`

Files inside a cluster folder describe WHAT they contain, not the layer.
The folder name already says "this is a service package", so the `_service`
suffix is redundant and must be dropped.

```
// GOOD — inside internal/app/auth/
auth/service.go          # main AuthService impl
auth/session.go          # SessionService impl
auth/oauth.go            # OAuthService impl

// BAD — redundant
auth/auth_service.go     # "auth" × 2 + "service" redundant
auth/session_service.go
auth/oauth_service.go
```

Exceptions:
- Test files keep `_test.go` suffix (Go requirement).
- The compat shim file at `internal/app/<cluster>_service.go` DOES carry
  the `_service` suffix because it lives in `package app`, not inside
  a named cluster folder.

Struct names keep the `Service` suffix (`AuthService`, `AssetService`) —
only file names are adjusted.

### 9. Layer-Mirrored Package Naming (`pkg/domain/<X>` ↔ `internal/app/<X>`)

It is intentional that `pkg/domain/audit/` and `internal/app/audit/` share the
short name `audit`. DDD convention — domain entities live at
`pkg/domain/<X>/`, the orchestrating service lives at `internal/app/<X>/`.

When a single file imports both, alias the domain side with a `dom` suffix:

```go
import (
    "github.com/openctemio/api/internal/app/audit"
    auditdom "github.com/openctemio/api/pkg/domain/audit"
)

var _ auditdom.Repository = (*audit.Service)(nil)
```

Do NOT rename folders to avoid the collision (do not add `svc`/`service`/
`app` suffix). Collisions handle at the callsite via alias; folder naming
stays mirrored with the domain layer for navigability.

---

## Domain Patterns

### Entity IDs

Use `shared.ID` types from `internal/domain/shared`:

```go
type ID = shared.ID

id, err := shared.IDFromString(input.RoleID)
if err != nil {
    return fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
}
```

### Error Handling

```go
// Domain errors (in domain/role/errors.go)
var (
    ErrRoleNotFound  = fmt.Errorf("%w: role not found", shared.ErrNotFound)
    ErrRoleInUse     = fmt.Errorf("%w: role is in use", shared.ErrConflict)
)

// Service layer — wrap with context
return fmt.Errorf("failed to delete role: %w", err)
```

### Repository Pattern

```go
// Interface in domain layer
type Repository interface {
    Create(ctx context.Context, r *Role) error
    GetByID(ctx context.Context, id ID) (*Role, error)
    Delete(ctx context.Context, id ID) error
}

// Implementation in infra/postgres — map sql.ErrNoRows → domain error
if errors.Is(err, sql.ErrNoRows) {
    return nil, role.ErrRoleNotFound
}
```

### CRITICAL: Tenant-Scoped Isolation

**Every repository query on multi-tenant tables MUST include `WHERE tenant_id = ?`.**

```go
// BAD — cross-tenant data leak
query := "SELECT * FROM findings WHERE id = $1"

// GOOD — tenant-scoped
func (r *FindingRepository) GetByID(ctx context.Context, tenantID shared.ID, id ID) (*Finding, error) {
    query := "SELECT * FROM findings WHERE tenant_id = $1 AND id = $2"
}
```

### Database Query Optimization

1. **Select specific columns** — avoid `SELECT *`
2. **Always paginate** — `LIMIT ? OFFSET ?` on list queries
3. **No N+1 queries** — use JOINs or batch loading
4. **Use ILIKE** for case-insensitive search (not `LOWER()`)
5. **JSONB** not JSON for indexed JSON data
6. **Create indexes in migrations** with `CREATE INDEX CONCURRENTLY`

### Cache Usage Guidelines

**Key Rules:**

- Always include `tenant_id` in cache keys: `fmt.Sprintf("t:%s:entity:%s", tenantID, id)`
- Always set TTL — never `redis.Set(ctx, key, value, 0)`
- Validate data before caching, not after
- Use Redis (not in-memory) for mutable data in multi-server environments
- Graceful degradation — app must work when Redis is down
- Use `singleflight.Group` to prevent cache stampede

**Critical Cache Pitfalls:**

1. **Multi-Tenant Cache Leaks** — Always include tenant in key AND double-check tenant matches on read
2. **No TTL** — Every key MUST have TTL (1 min to 24 hours based on data type)
3. **Cache Key Collisions** — Use structured naming: `entity:tenantID:id`
4. **Stale Data** — Always invalidate on write: `redis.Del(ctx, key)`
5. **Redis Downtime** — Try cache, log miss, fallback to DB, best-effort re-cache

**TTL Recommendations:**

| Data Type | TTL | Notes |
|-----------|-----|-------|
| User permissions | 5 min | Invalidate on role change |
| User sessions | 30 min | Standard session timeout |
| Configuration | 1 hour | Rarely changes |
| Query results | 1-5 min | Balance freshness vs load |

**Key Files:** `internal/infra/redis/`, `internal/app/permission_version_service.go`, `internal/app/session_service.go`

---

## Credentials Encryption

Integration credentials (access tokens, API keys) are encrypted using AES-256-GCM.

- `APP_ENCRYPTION_KEY`: 32-byte key (required in production)
  - Hex format: 64 characters (`openssl rand -hex 32`)
  - Base64 format: 44 characters (`openssl rand -base64 32`)
- If not set, credentials stored in plaintext (dev only)
- Existing plaintext credentials remain readable (backward compatible)

---

## 2-Layer Access Control

```
┌──────────────────────────────────────────────┐
│  LAYER 1: RBAC — User → Roles → Permissions │
│  "What can this user do?"                     │
├──────────────────────────────────────────────┤
│  LAYER 2: Groups — User → Groups → Data      │
│  "What data can this user see?"               │
└──────────────────────────────────────────────┘
```

> **Note:** `Module` entity exists as UI metadata only. No module-based route gating in OSS.

### Permission Middleware

```go
middleware.Require(permission.AssetsWrite)                              // Single
middleware.RequireAny(permission.AssetsRead, permission.ReposRead)      // OR
middleware.RequireAll(permission.AssetsWrite, permission.ReposWrite)     // AND
middleware.RequireAdmin()                                               // Owner or admin
middleware.RequireOwner()                                               // Owner only
```

**Owner-only operations:** `TeamDelete`, `BillingManage`, `GroupsDelete`, `PermissionSetsDelete`

**Route registration pattern:**

```go
r.Route("/assets", func(r chi.Router) {
    r.With(middleware.Require(permission.AssetsRead)).Get("/", h.List)
    r.With(middleware.Require(permission.AssetsWrite)).Post("/", h.Create)
    r.With(middleware.Require(permission.AssetsDelete)).Delete("/{id}", h.Delete)
})
```

**Permission check flow:**

- **Owner/Admin** (`isAdmin=true` in JWT): Bypass all permission checks
- **Member** (`isAdmin=false`): Check permissions array in JWT

### Permission Real-time Sync

JWT contains only `perm_version` (not full permissions array). Permissions cached in Redis.

```go
// Redis keys
perm_ver:{tenant_id}:{user_id}    // Current version (TTL: 30 days)
user_perms:{tenant_id}:{user_id}  // Cached permissions (TTL: 5 minutes)

// Increment version when roles change
permVersionService.Increment(ctx, tenantID, userID)
```

**Cache Invalidation Triggers:**

| Event | Cache Action | Version Action | Service |
|-------|-------------|----------------|---------|
| Role assigned/removed | Clear user cache | Increment version | `RoleService` |
| Role permissions changed | Clear all users with role | Increment affected users | `RoleService` |
| Member removed from tenant | Clear user cache | Delete version | `TenantService` |
| Session revoked | Clear all tenants cache | No change | `SessionService` |
| User suspended | Clear via session revoke | No change | `UserService` |

**Security guarantees:** All revocation operations (member removal, session revoke, user suspension) have **0-second window** — cache cleared immediately.

See `docs/architecture/permission-realtime-sync.md` for complete guide.

---

## Audit Logging

```go
event := NewSuccessEvent(audit.ActionRoleCreated, audit.ResourceTypeRole, r.ID().String()).
    WithResourceName(r.Name()).
    WithMessage(fmt.Sprintf("Role '%s' created", r.Name())).
    WithMetadata("slug", r.Slug()).
    WithSeverity(audit.SeverityMedium)
s.logAudit(ctx, actx, event)
```

---

## Notification System

Multi-channel notification system: Slack, Teams, Telegram, Email, custom webhooks.

### Key Concepts

**Event Types** (JSONB, no migration needed for new types):

```go
const (
    EventTypeFindings  EventType = "findings"
    EventTypeExposures EventType = "exposures"
    EventTypeScans     EventType = "scans"
    EventTypeAlerts    EventType = "alerts"
)
// Empty array = all events enabled (backward compatible)
```

**NotificationExtension** config: `enabledSeverities`, `enabledEventTypes`, `messageTemplate`, `includeDetails`, `minIntervalMinutes`.
Provider-specific config in `Integration.Metadata` (non-sensitive) and `Integration.CredentialsEncrypted` (sensitive).

**Adding new event type:** Add constant → update `AllKnownEventTypes()` → no migration needed.

**Adding new provider:** Create client in `internal/infra/notification/` implementing `Send()`, `TestConnection()`, `Provider()` → register in factory.

### Notification Outbox (Transactional Pattern)

```
┌──────────────────────────────────────────┐
│        SAME DATABASE TRANSACTION          │
│  1. INSERT INTO findings (...)            │
│  2. INSERT INTO notification_outbox       │
│  3. COMMIT                                │
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│        WORKER (Polling-based)             │
│  1. SELECT ... FOR UPDATE SKIP LOCKED     │
│  2. Send to matching integrations         │
│  3. UPDATE status = 'completed'           │
└──────────────────────────────────────────┘
```

**Status lifecycle:** `pending → processing → [ARCHIVE to notification_events] → [DELETE from outbox]`
Failed entries retry with exponential backoff → `dead` after max retries.

**Usage in services:**

```go
tx, err := s.db.BeginTx(ctx, nil)
defer func() { _ = tx.Rollback() }()

finding, err := s.findingRepo.CreateInTx(ctx, tx, finding)

err = s.notificationService.EnqueueNotificationInTx(ctx, tx, app.EnqueueNotificationParams{
    TenantID:  tenantID,
    EventType: "new_finding",
    Title:     fmt.Sprintf("New %s Finding: %s", finding.Severity, finding.Title),
    Severity:  finding.Severity.String(),
})

return tx.Commit() // Both or neither succeed
```

**Key Files:** `internal/domain/notification/`, `internal/app/notification_service.go`, `internal/app/notification_scheduler.go`

For detailed docs, see `docs/architecture/notification-system.md`.

### Per-Tenant SMTP

Transactional emails (invitations, verification, password reset) support per-tenant SMTP configuration via the email notification integration.

**Resolution order:** Tenant email integration (if active) → System SMTP (`SMTP_HOST` env vars) → Skip (log warning).

```go
// TenantSMTPResolver interface (internal/app/email_service.go)
type TenantSMTPResolver interface {
    GetTenantSMTPConfig(ctx context.Context, tenantID string) (*email.Config, error)
}

// Implementation: IntegrationSMTPResolver (internal/app/tenant_smtp_resolver.go)
// Reads SMTP config from integration metadata:
//   smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, smtp_from_name, smtp_tls
```

**Key Files:** `internal/app/email_service.go`, `internal/app/tenant_smtp_resolver.go`

### User Management (Production)

In production, disable public registration: `AUTH_ALLOW_REGISTRATION=false`

Users are added via the invitation system:

```go
// 1. Admin creates invitation (requires team:admin)
POST /api/v1/tenants/{tenant}/invitations
{"email": "user@company.com", "role_ids": ["00000000-0000-0000-0000-000000000003"]}

// System roles (pre-seeded, tenant_id=NULL):
//   00000000-...-000000000001  owner
//   00000000-...-000000000002  admin
//   00000000-...-000000000003  member
//   00000000-...-000000000004  viewer

// 2. User accepts via token link
POST /api/v1/invitations/{token}/accept-with-refresh
```

**Key Files:** `internal/app/tenant_service.go` (CreateInvitation), `internal/infra/http/handler/tenant_handler.go`

---

## Platform Agents Architecture (v3.2)

Platform Agents are OpenCTEM-managed agents running on shared infrastructure across all tenants.

### Key Components

1. **Platform Agent Entity** — `IsPlatformAgent bool`, stats, selection
2. **Bootstrap Token** — Kubeadm-style tokens for self-registration (usage limits, expiration)
3. **Queue Management** — Weighted Fair Queuing with age bonus, `FOR UPDATE SKIP LOCKED`

### Key Files

```
internal/
├── domain/
│   ├── agent/           # entity.go, bootstrap_token.go, errors.go, repository.go
│   ├── lease/           # K8s-style lease entity
│   └── admin/           # AdminUser entity (super_admin, ops_admin, readonly)
├── infra/
│   ├── postgres/        # agent_repository, bootstrap_token_repository, lease_repository
│   ├── controller/      # agent_health, job_recovery, queue_priority, token_cleanup
│   └── http/
│       ├── handler/     # platform_handler, platform_register_handler, platform_agent_handler, platform_job_handler
│       ├── middleware/   # platform_auth, admin_auth, ratelimit
│       └── routes/      # platform.go
└── app/                 # platform_agent_service, lease_service
```

### API Endpoints

**Registration (Public, Rate Limited):**
- `POST /api/v1/platform/register` — Self-registration with bootstrap token
- `POST /api/v1/platform-agents/register` — Alternative endpoint

**Agent Communication (API Key Auth):**
- `PUT/DELETE /api/v1/platform/lease` — Renew/release lease
- `POST /api/v1/platform/poll` — Long-poll for jobs
- `POST /api/v1/platform/jobs/{id}/ack|result|progress` — Job lifecycle

**Tenant Job Submission (JWT Auth):**
- `POST /api/v1/platform-jobs/` — Submit job
- `GET /api/v1/platform-jobs/` — List/get jobs
- `POST /api/v1/platform-jobs/{id}/cancel` — Cancel job

---

## Security Checklist

### 1. Rate Limiting for Public Endpoints

```go
// BAD - No rate limiting
r.POST("/register", registerHandler.Register)

// GOOD - Apply rate limiting
r.POST("/register", registerHandler.Register, middleware.RateLimit(10, time.Minute))
```

### 2. Generic Error Messages

**NEVER expose internal state through error messages:**

```go
// BAD — leaks token state
apierror.Unauthorized("bootstrap token is not usable: " + err.Error())

// GOOD — generic error, log details internally
apierror.Unauthorized("Invalid or expired token").WriteJSON(w)
h.logger.Warn("token validation failed", "reason", err.Error())
```

| BAD Message | Attack Vector |
|-------------|---------------|
| "token has expired" | Attacker knows token was once valid |
| "token usage limit reached" | Attacker knows max_uses |
| "user not found" vs "invalid password" | User enumeration |

### 3. Constant-Time Comparison

```go
// BAD — timing attack vulnerable
if providedHash == storedHash { ... }

// GOOD
if subtle.ConstantTimeCompare([]byte(providedHash), []byte(storedHash)) == 1 { ... }
```

### 4. API Keys in Headers Only

```go
// BAD — API key in URL (logged by proxies)
apiKey := r.URL.Query().Get("api_key")

// GOOD
apiKey := r.Header.Get("X-API-Key")
```

### 5. Sensitive Data in Request Body

```go
// BAD — Token in URL
POST /api/v1/register?token=secret

// GOOD — Token in body
POST /api/v1/register  {"bootstrap_token": "secret"}
```

---

## Common Mistakes to Avoid (Lessons Learned)

### 1. Type Name Conflicts in Handler Package

```go
// BAD — RegisterRequest already exists in local_auth_handler.go
type RegisterRequest struct { ... }

// GOOD — Prefix with domain
type PlatformRegisterRequest struct { ... }
```

### 2. Missing Bounds Validation

```go
// BAD
req.LeaseDurationSeconds // Could be MaxInt64

// GOOD
if req.LeaseDurationSeconds < 10 || req.LeaseDurationSeconds > 300 {
    apierror.BadRequest("lease_duration_seconds must be between 10-300").WriteJSON(w)
}
```

### 3. Handler Defaults vs Service Defaults

```go
// BAD — Handler sets defaults
if req.MaxJobs <= 0 { req.MaxJobs = 5 }

// GOOD — Service handles defaults
if input.MaxJobs <= 0 { input.MaxJobs = DefaultMaxJobs }
```

### 4. Transaction Boundaries

```go
// BAD — Separate operations
agentRepo.Create(ctx, agent)
leaseRepo.Create(ctx, lease) // If this fails, orphan agent

// GOOD — Atomic
tx, _ := db.BeginTx(ctx, nil)
defer func() { _ = tx.Rollback() }()
agentRepo.CreateTx(ctx, tx, agent)
leaseRepo.CreateTx(ctx, tx, lease)
tx.Commit()
```

### 5. Context Extraction Duplication

```go
// BAD — Copy-paste in every handler
agt := middleware.GetPlatformAgentFromContext(r.Context())
if agt == nil { apierror.Unauthorized("...").WriteJSON(w); return }

// GOOD — Helper method
func (h *Handler) requireAgent(r *http.Request) (*agent.Agent, error) {
    agt := middleware.GetPlatformAgentFromContext(r.Context())
    if agt == nil { return nil, ErrNotAuthenticated }
    return agt, nil
}
```

### 6. Scan Method Duplication

```go
// BAD — 95% duplicate code
func scanLease(row *sql.Row) (*Lease, error) { /* 80 lines */ }
func scanLeaseFromRows(rows *sql.Rows) (*Lease, error) { /* 79 lines */ }

// GOOD — Shared scanner interface
type rowScanner interface { Scan(dest ...interface{}) error }
func (r *Repository) scanLease(scanner rowScanner) (*Lease, error) { /* single impl */ }
```

### 7. Don't Swallow Errors Silently

```go
// BAD — client sees empty result
if err != nil {
    h.logger.Error("failed to get jobs", "error", err)
    // Returns empty jobs — client can't distinguish from "no jobs"
}

// GOOD — return error to client
if err != nil {
    apierror.InternalServerError("job retrieval failed").WriteJSON(w)
    return
}
```

### 8. Consolidate Auth Errors (Anti-Enumeration)

```go
// BAD — different errors reveal internal state
if !agt.IsPlatformAgent { apierror.Forbidden("Not a platform agent") }
if agt.Status != Active  { apierror.Forbidden("Agent is not active") }

// GOOD — generic error, log specifics server-side
h.logger.Debug("auth failed", "reason", "not platform agent")
apierror.Unauthorized("Invalid credentials").WriteJSON(w)
```

### 9. Multiple Endpoints — Same Security Controls

```go
// Both registration endpoints MUST share the same rate limiter:
platformRegRateLimiter := middleware.NewPlatformRegistrationRateLimiter(cfg, log)
registerPlatformAgentRoutes(router, h, auth, userSync, platformRegRateLimiter.Middleware())
registerPlatformCommunicationRoutes(router, platformH, registerH, platformRegRateLimiter.Middleware())
```

### 10. Switch Case Consolidation

```go
// BAD — repetitive cases with same response
case errors.Is(err, agent.ErrBootstrapTokenInvalid):
    apierror.Unauthorized("Invalid token").WriteJSON(w)
case errors.Is(err, agent.ErrBootstrapTokenExpired):
    apierror.Unauthorized("Invalid token").WriteJSON(w)

// GOOD — consolidate
case errors.Is(err, agent.ErrBootstrapTokenInvalid),
    errors.Is(err, agent.ErrBootstrapTokenExpired),
    errors.Is(err, agent.ErrBootstrapTokenExhausted):
    apierror.Unauthorized("Invalid or expired bootstrap token").WriteJSON(w)
```

---

## SDK Security Notes

- SDK validates jobs client-side, but **the API is the authoritative validator**
- SDK uses `credentials.SecureCompare()` — the API should also use constant-time comparison
- The server must validate templates before sending to agents (path traversal protection)

---

## Smart Filtering (Asset-Scanner Compatibility)

Smart filtering matches assets to compatible scanners based on `supported_targets`.

**How it works:**
1. **At scan creation** — `PreviewScanCompatibility()` warns about incompatible assets (never blocks)
2. **At scan trigger** — `filterAssetsForSingleScan()` filters by tool's `supported_targets`

**Design principles:** Never block, transparent (show scanned vs skipped), graceful degradation, unclassified = skipped.

**Key files:** `internal/app/scan/filtering.go`, `internal/app/scan/trigger.go`, `internal/domain/tool/target_mapping.go`

---

## Common Commands

```bash
make run          # Run server
make dev          # Run with hot reload
make test         # Run tests
make migrate-up   # Run migrations
make mocks        # Generate mocks
make fmt          # Format code
openssl rand -hex 32  # Generate encryption key
```

See [`docs/MAKEFILE.md`](./docs/MAKEFILE.md) for complete reference.

---

## Git Commit Guidelines

- **No Co-Authored-By** or Generated-By lines
- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`

```bash
git commit -m "fix(security): add input validation

- Add LIKE pattern escaping
- Fix ORDER BY validation
"
```

---

## Recent Changes (2026-04-15)

### Asset Identity Resolution (RFC-001)
- Asset names normalized automatically in `NewAsset()` constructor (16 asset types)
- IP correlation for host dedup (`internal/app/ingest/correlator.go`)
- Aliases stored in `properties.aliases[]` when assets renamed
- Admin dedup review: `GET/POST /api/v1/assets/dedup/reviews`
- Per-tenant config: `tenant.Settings.AssetIdentity`
- See `docs/architecture/asset-identity-resolution.md`

### API Decoupled from SDK-Go (RFC-002)
- API imports `github.com/openctemio/ctis` (4K lines, zero deps) instead of SDK-Go (50K lines)
- Adapters copied to `internal/infra/adapters/`
- Branch: `feat/decouple-sdk` (pending merge)
- See `docs/architecture/api-ctis-decoupling.md`

### Asset metadata column removed
- `metadata` JSONB merged into `properties` (migration 000140)
- Entity: `Metadata()` and `SetMetadata()` removed
- API response: only `properties` field (no more `metadata`)

### Sub-type promotion
- Ingest now resolves TypeAliases and promotes `sub_type` from properties
- Migration 000141 backfills existing data

### CTEM loop closures (2026-04-20)
- Migration 000154 — audit log hash-chain (tamper-evident trail)
- Migration 000155 — runtime telemetry events (EDR/XDR ingest from agents)
- Migration 000156 — IOC catalogue + match log (runtime auto-reopen, B6)
- Agent API-key endpoint: `POST /api/v1/telemetry-events` (NOT `/runtime-telemetry/events`)
- Admin endpoint: `GET /api/v1/audit-logs/verify` returns 409 when chain broken
- Package `pkg/domain/ioc/`, `pkg/domain/telemetry/`, `internal/app/ioc/` added
- Priority-flood guard renamed: `P0FloodGuard` → `PriorityFloodGuard` with configurable `ProtectedClass`
- Q1/Q2/Q3 gate integration tests in `tests/integration/ctem_*_test.go`

### Security hardening batch (2026-04-22)
- **SSRF two-tier guard**: `api/pkg/httpsec` exports `hardBlockedIPRanges` (always-blocked: IMDS, loopback, CGNAT, multicast, broadcast, v6 link-local) and `privateIPRanges` (RFC1918 + ULA, soft-blocked). Opt-in via `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1`. Mirrored identically in `sdk-go/pkg/httpsec/`.
  - Any new outbound HTTP must use `httpsec.SafeHTTPClient`. CI (`scripts/security-lint.sh` Rule 1) fails on raw `&http.Client{}` outside `pkg/httpsec`.
- **CSRF middleware**: `internal/infra/http/middleware/csrf.go` — double-submit-cookie on every JWT-cookie state-changing route. Exempt list is explicit (API-key + HMAC webhook). Emits `openctem_security_csrf_rejections_total` with `reason` label.
- **Startup sentinel**: `internal/config/config.go` — `isDevDefaultJWTSecret` / `isDevDefaultEncryptionKey` gate refuses boot when `APP_ENV != development`. Also refuses `APP_DEBUG=true`, `CORS=*`, `DB_SSLMODE=disable` in production.
- **Audit chain verifier**: `internal/infra/controller/audit_chain_verify.go` — hourly re-walk; emits `level=error alert=audit_chain_break` + `openctem_security_audit_chain_breaks_total`.
- **AI-triage budget**: migration `000163_ai_triage_budgets`, `internal/app/aitriage/budget.go`, `internal/infra/postgres/ai_triage_budget_repository.go`. Uses `INSERT…ON CONFLICT DO NOTHING` for GetOrCreate and `UPDATE…RETURNING` for IncrementUsed. Ships disabled; rollout in [RFC-008](../docs/rfcs/RFC-008-llm-token-budget.md).
- **Prompt-injection defences**: `TriageResult.ValidationWarnings` + `NeedsReview()` in `pkg/domain/aitriage/entity.go`. Downstream workflow payload has `needs_review` flag; emits `ActionAITriageNeedsReview` audit event.
- **Email CRLF sanitiser**: `pkg/email/email.go` exports `SanitizeHeaderValue`. Use it for any user-controlled string fed into SMTP headers.
- **Security observability**: 5 new Prometheus series under `openctem_security_*` prefix. See `internal/metrics/security_defenses.go`.
- **Slice CodeQL fix**: use const-literal capacity passed directly to `make()` for `go/unsafe-slice-allocation` clean-flow (see `finding_approval_repository.go`, `tenant_repository.go`).

### Migrations: 163 total (000001–000163)

**Last Updated**: 2026-04-22
