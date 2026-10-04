# API Project - Claude AI Assistant Guidelines

> Essential coding standards and patterns for the OpenCTEM API (Go backend).

## Project Context

This is `api/` in the `openctemio/openctem` monorepo (formerly the `openctemio/api`
repository, renamed 2026-10-02; RFC-020). The repository holds two components:

- `api/` (this): the Go API, module `github.com/openctemio/openctem/api`.
- `web/`: the Next.js web console (formerly `openctemio/ui`, now archived). See `../web/CLAUDE.md`.

Separate repositories: [sensor](https://github.com/openctemio/sensor) (formerly
agent), [sdk-go](https://github.com/openctemio/sdk-go),
[ctis](https://github.com/openctemio/ctis),
[helm-charts](https://github.com/openctemio/helm-charts) and the public
[docs](https://github.com/openctemio/docs) site. Map:
`docs/development/repositories.md`.

- **Docs**: `./docs/`: architecture, RFCs, development guides, user guide.
- **Root**: `../Makefile` (`make setup`, `make hooks`, `make check`, …), `../.github/workflows/`
  (all CI; see `docs/development/ci-cd.md`), `../.githooks/`, `../CLAUDE.md` (rules that span both).
- **Contract**: after changing a handler's request/response run `make swagger` here, then
  `make api-types` at the root, and commit both (Web CI fails on drift).
- **Release**: one `vX.Y.Z` tag on `main` releases API + web together (`ghcr.io/openctemio/openctem-api`,
  `openctem-web`, all-in-one `openctem`, `migrations`, `seed`, `admin-cli`).

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
    "github.com/openctemio/openctem/api/internal/app/audit"
    auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
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
┌────────────────────────────────────────────────────────┐
│  LAYER 1: RBAC — User → Roles → Permissions            │
│  "What can this user do?"                              │
├────────────────────────────────────────────────────────┤
│  LAYER 2: Data scope — which assets this user can see  │
│  = assets of the user's active groups                  │
│  + explicit per-user grants (asset_access_grants)      │
└────────────────────────────────────────────────────────┘
```

**Layer 2 (data scope)** rows live in `user_accessible_assets`, computed from
exactly two sources:

- **Group assignment:** the assets assigned to the user's active groups
  (`asset_owners` rows with a `group_id`: Groups → Assets, scope rules, or a
  group owner on an asset), managed with `team:groups:write`.
- **Explicit grant:** one user, one asset, in `asset_access_grants`
  (migration `000372`), managed with `team:groups:write` through
  `GET/POST/DELETE /api/v1/assets/{id}/access-grants`.

**Being an asset owner is not a scope grant** (owner decision O1,
2026-10-03): naming a *user* as an owner is an assignment (accountability,
finding assignment, notifications) and never changes what that user can see.
Owners/admins and internal calls with no user are never restricted; a member
with no scope row sees what `tenants.members_without_group_see` says
(`everything` or `nothing`). By-id access is enforced in
`internal/app/datascope` (out of scope answers 404, never 403). Full model:
`docs/architecture/authorization-matrix.md`, section "Data scope".

> **Note:** Module route gating IS live: `RequireModule` (`internal/infra/http/middleware/module_gate.go`) gates ~26 route groups. It is a **fail-open feature flag, NOT a security boundary** (nil/error/unknown → allow) and has **no admin bypass** (unlike permission checks). A request must pass BOTH the module gate (feature on for tenant) AND the permission check.

### Permission Middleware

```go
middleware.Require(permission.AssetsWrite)                              // Single
middleware.RequireAny(permission.AssetsRead, permission.ReposRead)      // OR
middleware.RequireAll(permission.AssetsWrite, permission.ReposWrite)     // AND
middleware.RequireAdmin()                                               // Owner or admin
middleware.RequireOwner()                                               // Owner only
```

**Owner-only operations:** `TeamDelete`, `BillingManage`, `GroupsDelete`, `AssignmentRulesDelete`

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
- **Member** (`isAdmin=false`): Check the permissions `EnrichPermissions` resolved for this request (the JWT array is only a fallback; see below)

### Permission Real-time Sync

JWT currently carries both `perm_version` AND the full permissions array (the "slim token" migration is incomplete — `GenerateSlimAccessToken` is unused). Do NOT treat the JWT array as authoritative: the permission-sync middleware (`EnrichPermissions`) re-resolves fresh permissions from Redis/DB on every tenant-scoped request and returns 409 on a stale write, so revocation takes effect on the next request. Permissions are cached in Redis with a per-user version.

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

### Working with authorization — rules & recipes

The settled model, the how-to recipes, and the CI invariants live in
**`docs/architecture/authorization-matrix.md`** (canonical) — read it before
touching any gate. In short:

- **Gate every new route** with the least-privilege `middleware.Require(permission.X)`
  (or `RequireTeamAdmin/Owner` for `/tenants/{tenant}/*`). Genuinely public/self
  routes must be added to `allowlistPrefixes` in `route_authz_coverage_test.go` **with
  a reason** — that test fails the build on any ungated, un-allowlisted route.
- **Classify every new route's data scope** in `dataSurfaceRegistry`
  (`tests/unit/route_scope_classification_test.go`): scoped, partial, gap (with
  its research id), separate, config or system. CI fails on an unclassified route.
- **Add a permission** in three synced places: `permission.go` (`AllPermissions()`) +
  a numbered DB seed migration (additive, with a `.down.sql`) + the UI TS constants.
  `permission_catalog_sync_test.go` fails if Go and DB disagree.
- **Object-level authz is separate from route gating:** every mutating query must
  carry `AND tenant_id = $n`; derive the principal's tenant from the authenticated
  context (sensors: from the sensor key), never from the request body.
- **Gate granularly** — use the precise permission for an action (`findings:status`,
  not `findings:write`) so the role matrix is honest.

**Prohibitions:**
- Never treat the frontend perm check as the boundary — backend is the only authority.
- Never rely on the module gate for security — it is fail-open by design.
- Never widen a route's gate to "make a role work" — adjust the role's grant via seed/migration.
- No `expires_at`/time-boxed grants and no permission-set deny-gate (deliberate — see the doc).
- Don't change an organization's data-scope policy (`tenants.members_without_group_see`: existing orgs `everything`, new orgs `nothing`) in a migration, and don't unify admin/owner oracles, without signoff.

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

Public registration is **off by default** (`AUTH_ALLOW_REGISTRATION=false`,
RFC-025). People get accounts from an administrator, an invitation, or their
organization's SSO (JIT on verified domains). See
`docs/architecture/user-onboarding.md`.

Administrators create users directly (one-time set-password link, emailed or
returned once as `setup_token`):

```go
POST /api/v1/tenants/{tenant}/users        // owner/admin
{"email": "user@company.com", "name": "User", "role_ids": ["00000000-0000-0000-0000-000000000004"]}
POST /api/v1/admin/tenants/{tenantId}/users // platform admin console: FIRST OWNER ONLY (409 once an owner exists)
```

Or invite (invitees without an account register with the invitation token):

```go
// 1. Admin creates invitation (requires team:admin)
POST /api/v1/tenants/{tenant}/invitations
{"email": "user@company.com", "role_ids": ["00000000-0000-0000-0000-000000000003"]}

// System roles (pre-seeded, tenant_id=NULL):
//   00000000-...-000000000001  owner
//   00000000-...-000000000002  admin
//   00000000-...-000000000003  member
//   00000000-...-000000000004  viewer

// 2. User opens the emailed link (/invitations#token=..., the token in the
//    fragment) and accepts; the token always travels in the body:
POST /api/v1/invitations/accept-with-refresh   {"token": "..."}
```

**Key Files:** `internal/app/tenant_service.go` (CreateInvitation), `internal/infra/http/handler/tenant_handler.go`

---

## Sensors (formerly "agents") — RFC-023

### Glossary

| Term | Meaning in this code base |
|---|---|
| **Sensor** | Customer-side software that authenticates *to* the platform with its own key (`octs_…`; legacy `rda_…`) and heartbeat. Umbrella term; one row in `sensors`. |
| Scanner / Agent / Collector | Sensor **roles** (RFC-023 D18). *Agent* now means only the endpoint role. |
| `type` | Legacy v1 value (`worker`, `scanner`, `sensor`, `collector`, `runner`), kept as input and storage. |
| Platform sensor | `is_platform_sensor = true`: shared infrastructure, no tenant. |
| AI agent | AI-triage mode `agent` (`AIModeAgent`, module `ai_triage.agent`) — an LLM agent, not a sensor. |
| Protocol v1 | What deployed sensors speak: `/api/v1/agent/*`, `agent_id` in responses. Frozen; lives only in `pkg/sensorproto/legacyv1`. |

The rename is complete (RFC-023 §9.5, migration 000230): packages, types,
tables/columns, permissions `sensors:*`, management API `/api/v1/sensors`
(`/api/v1/agents` → 308), audit ids `sensor.*`, log field `sensor_id`, env
`SENSOR_*` (old `AGENT_*` still read with a warning).

**Rules**
- Never add an identifier containing "agent" for a sensor concept —
  `tools/lint/sensorvocab` fails CI. Wire vocabulary that deployed sensors need
  goes in `pkg/sensorproto/legacyv1`; the v1 wire is pinned by
  `internal/infra/http/handler/protocol_v1_golden_db_test.go`.
- A branch written before the rename catches up with `scripts/rename/sensor-rename.sh`.
- Historical audit rows (`agent.*`) and asset state history (`source='agent'`)
  are never rewritten; reads use `audit.WithHistoricalActions` /
  `asset.WithHistoricalSources`.
- After a migration run, `./server -sensor-upgrade-check` confirms no
  pre-rename data is left.

### Key Files

```
pkg/domain/sensor/                 # entity, API keys, errors, repository interfaces
pkg/sensorproto/legacyv1/          # protocol v1 + /api/v1/agents redirect + renamed env vars
pkg/sensorproto/v2/                # protocol v2 results wire (RFC-026): media type, problems, status, hello
internal/infra/http/routes/sensor_v2.go  # /api/v2/sensor (own sensor-key authenticator + edge chain)
internal/app/ingest/v2*.go         # v2 accept (receiver), segment semantics, commit + blinding guard, jobs
internal/app/sensor/               # service, selector, config templates
internal/infra/postgres/           # sensor_repository, sensor_apikey_repository, sensor_upgrade_check
internal/infra/controller/         # sensor_health
internal/infra/http/handler/       # sensor_handler (management), ingest/command/scansession (v1)
internal/infra/http/routes/        # scanning.go: /api/v1/sensors + v1 mounts
pkg/domain/sensor/event.go, activity.go, build.go  # activity timeline (heartbeat diff), build/SDK info
internal/infra/postgres/sensor_event_repository.go  # sensor_events + merged timeline (events, commands, audit)
pkg/domain/scanzone/               # scan zones: range validation, router (RFC-023 Phase 1)
internal/app/scan/zones.go         # trigger-time zone routing, batching, pinning
internal/app/scanzone/             # zone CRUD, sensor assignment, coverage
```

Scan zones: once a tenant has zones, network scans are routed to the narrowest
zone and pinned to its sensors, and `commands.scan_zone_id` restricts poll and
acknowledge to the zone's sensors (`zoneClaimPredicate`). Tenants without zones
are unaffected. See `docs/architecture/scan-zones.md`.

See `docs/architecture/sensors.md` and `docs/rfcs/RFC-023-sensor-rename-contract.md`.

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
sensorRepo.Create(ctx, sensor)
leaseRepo.Create(ctx, lease) // If this fails, orphan sensor

// GOOD — Atomic
tx, _ := db.BeginTx(ctx, nil)
defer func() { _ = tx.Rollback() }()
sensorRepo.CreateTx(ctx, tx, sensor)
leaseRepo.CreateTx(ctx, tx, lease)
tx.Commit()
```

### 5. Context Extraction Duplication

```go
// BAD — Copy-paste in every handler
agt := middleware.GetPlatformSensorFromContext(r.Context())
if agt == nil { apierror.Unauthorized("...").WriteJSON(w); return }

// GOOD — Helper method
func (h *Handler) requireSensor(r *http.Request) (*sensor.Sensor, error) {
    agt := middleware.GetPlatformSensorFromContext(r.Context())
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
if !agt.IsPlatformSensor { apierror.Forbidden("Not a platform sensor") }
if agt.Status != Active   { apierror.Forbidden("Sensor is not active") }

// GOOD — generic error, log specifics server-side
h.logger.Debug("auth failed", "reason", "not platform sensor")
apierror.Unauthorized("Invalid credentials").WriteJSON(w)
```

### 9. Multiple Endpoints — Same Security Controls

```go
// Both registration endpoints MUST share the same rate limiter:
platformRegRateLimiter := middleware.NewPlatformRegistrationRateLimiter(cfg, log)
registerPlatformSensorRoutes(router, h, auth, userSync, platformRegRateLimiter.Middleware())
registerPlatformCommunicationRoutes(router, platformH, registerH, platformRegRateLimiter.Middleware())
```

### 10. Switch Case Consolidation

```go
// BAD — repetitive cases with same response
case errors.Is(err, sensor.ErrBootstrapTokenInvalid):
    apierror.Unauthorized("Invalid token").WriteJSON(w)
case errors.Is(err, sensor.ErrBootstrapTokenExpired):
    apierror.Unauthorized("Invalid token").WriteJSON(w)

// GOOD — consolidate
case errors.Is(err, sensor.ErrBootstrapTokenInvalid),
    errors.Is(err, sensor.ErrBootstrapTokenExpired),
    errors.Is(err, sensor.ErrBootstrapTokenExhausted):
    apierror.Unauthorized("Invalid or expired bootstrap token").WriteJSON(w)
```

---

## SDK Security Notes

- SDK validates jobs client-side, but **the API is the authoritative validator**
- SDK uses `credentials.SecureCompare()` — the API should also use constant-time comparison
- The server must validate templates before sending to sensors (path traversal protection)

---

## Smart Filtering (Asset-Scanner Compatibility)

Smart filtering matches assets to compatible scanners based on `supported_targets`.

**How it works** (RFC-042 §6.3.8 O6: enforcing, keyed on the stored (type, sub_type)):
1. **At scan creation** — `PreviewScanCompatibility()` warns about incompatible assets (never blocks creation)
2. **At scan trigger** — `resolveScanTargets()` leaves out asset-group members the scanner cannot scan (registry `scannable_by` + active admin target mappings); nothing left → `NO_COMPATIBLE_TARGETS` (400). `filterAssetsForSingleScan()` reports the same split
3. **At every workflow step** — `FilterStepTargets()` gates the run's typed targets for the step's tool before the sensor command is built (both dispatchers); nothing left → the step fails with `INCOMPATIBLE_TARGETS`

**Design principles:** a scanner is never handed a type it cannot scan; transparent (counts and a reason per type); undecidable (unclassified, unknown type, tool without target types) = dispatched; direct targets have no stored type and are not type-gated; `target_types` in the run context never reaches a sensor.

**Key files:** `internal/app/scan/type_gate.go`, `internal/app/scan/compatibility.go`, `internal/app/scan/filtering.go`, `internal/app/scan/targets.go`, `pkg/domain/tool/target_mapping.go`

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

## Where to find recent changes

This file describes conventions, not history, so it keeps no change log and
no counts that go stale:

- **What changed:** `git log` on `develop`, `CHANGELOG.md`, and the RFC index
  (`docs/rfcs/README.md`), which maps each design to its implementation PRs.
- **Migrations:** the numbers are not contiguous (renumbering leaves gaps), so
  do not count them. The newest is
  `ls migrations/*.up.sql | sort | tail -1`. A new migration takes the next
  number above the highest on `develop` and in open PRs.

## Local builds: `GOWORK=off`

The monorepo has no `go.work`, but a `go.work` in a parent directory (for example
a workspace checkout that lists `sdk-go` or `sensor`) would still be picked up and
can fail with `cannot load module … listed in go.work`. **Run Go from `api/` with
`GOWORK=off`**, which is what CI does (and what the root `Makefile` does):

```bash
GOWORK=off go build ./...
GOWORK=off go test ./...
GOWORK=off golangci-lint run ./...
```

**Last Updated**: 2026-10-04
