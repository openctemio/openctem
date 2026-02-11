# API Project - Claude AI Assistant Guidelines

> Essential coding standards and patterns for the OpenCTEM API (Go backend).

## Project Context

This is the **API** sub-project of the OpenCTEM Platform workspace. For workspace-level guidelines, see [`../CLAUDE.MD`](../CLAUDE.MD).

**Related Projects:**

- [`../ui/`](../ui/) - Frontend UI (Next.js)
- [`../agent/`](../agent/) - AI Agent service
- [`../sdk/`](../sdk/) - SDK libraries
- [`../docs/`](../docs/) - Global documentation (GitHub Pages)

## Documentation Location

- **Local docs**: `./docs/` - API-specific documentation
- **Global docs**: `../docs/` - Workspace-level GitHub Pages docs (Jekyll + just-the-docs theme)

When referring to "docs" in this project context → means local `./docs/`

---

## Test-Driven Development (TDD)

**CRITICAL:** When implementing any new feature or significant change:

1. **Research thoroughly** before writing code
   - Analyze requirements and objectives
   - Identify ALL use cases and edge cases
   - Understand boundary conditions and special scenarios
   - Review existing tests and patterns

2. **Write Unit Tests FIRST** before implementation
   - Write tests to cover ALL use cases
   - Write tests for ALL edge cases
   - Tests must fail initially (no implementation yet)
   - Tests must be clear, understandable, and maintainable
   - Follow existing test patterns in the codebase

3. **Develop the feature** to pass tests
   - Implement code to pass each test
   - Refactor code to improve quality
   - Ensure all tests pass
   - Do not skip any failing tests

**Benefits:**

- Ensures high code coverage
- Catches bugs early
- Code is easier to maintain and refactor
- Tests serve as documentation
- Confidence when changing code

**Test Files Location:**

- Unit tests: `api/tests/unit/`
- Integration tests: `api/tests/integration/`
- Repository tests: `api/tests/repository/`

**Running Tests:**

```bash
# Run all tests
make test

# Run specific test file
go test -v ./tests/integration/ingest_finding_test.go

# Run with coverage
go test -cover ./...

## Tech Stack

- **Go 1.25+** with strict linting via golangci-lint
- **PostgreSQL** for persistence
- **Chi Router** for HTTP routing
- **Domain-Driven Design** architecture

## Project Structure

```
api/
├── cmd/                    # Application entrypoints
├── internal/
│   ├── app/               # Application services (business logic)
│   ├── domain/            # Domain models and interfaces
│   │   ├── shared/        # Shared domain types (ID, errors)
│   │   ├── role/          # RBAC roles
│   │   ├── permission/    # Permissions
│   │   └── ...
│   └── infra/             # Infrastructure layer
│       ├── http/          # HTTP handlers, routes, middleware
│       └── postgres/      # Database repositories
├── pkg/                   # Public packages
├── migrations/            # Database migrations
└── docs/                  # Local documentation
```

## Linting Rules & Common Issues

### 1. Error Comparison (errorlint)

**Always use `errors.Is()` instead of `==` for error comparison.**

```go
// BAD - comparing with == will fail on wrapped errors
if err == sql.ErrNoRows {
    return ErrNotFound
}

// GOOD - use errors.Is for proper wrapped error handling
if errors.Is(err, sql.ErrNoRows) {
    return ErrNotFound
}
```

### 2. Pre-allocate Slices (prealloc)

**Pre-allocate slices when the capacity is known.**

```go
// BAD - slice grows dynamically
var items []Item
for _, id := range ids {
    items = append(items, getItem(id))
}

// GOOD - pre-allocate with known capacity
items := make([]Item, 0, len(ids))
for _, id := range ids {
    items = append(items, getItem(id))
}
```

### 3. Use Constants (goconst)

**Use constants for repeated string literals. Common constants are in `internal/infra/postgres/constants.go`.**

```go
// Available constants
const (
    sortOrderASC       = "ASC"
    sortOrderDESC      = "DESC"
    sortOrderDescLower = "desc"
    sortFieldName      = "name"
    sortFieldPriority  = "priority"
    sortFieldCreatedAt = "created_at"
)

// BAD
orderDir := "ASC"
if desc {
    orderDir = "DESC"
}

// GOOD
orderDir := sortOrderASC
if desc {
    orderDir = sortOrderDESC
}
```

### 4. Check Error Returns (errcheck)

**Always check error return values, especially in defer.**

```go
// BAD - unchecked error
defer tx.Rollback()

// GOOD - explicitly ignore error in defer
defer func() { _ = tx.Rollback() }()
```

### 5. File Formatting (goimports)

**Run `goimports` before committing. Use tabs for indentation.**

```bash
# Format all files
goimports -w ./...

# Or use make target
make fmt
```

### 6. Integer Overflow (gosec)

**Add bounds checking when converting between integer types.**

```go
// BAD - potential overflow
value := int32(someInt)

// GOOD - check bounds first
if someInt > math.MaxInt32 || someInt < math.MinInt32 {
    return fmt.Errorf("value %d overflows int32", someInt)
}
value := int32(someInt)
```

### 7. Cyclomatic Complexity (cyclop)

**Keep functions under 30 cyclomatic complexity. For route registration and similar cases, use nolint directive.**

```go
//nolint:cyclop // Route registration naturally has many branches
func RegisterRoutes(...) {
    // ...
}
```

## Domain Patterns

### Entity IDs

Use domain-specific ID types from `internal/domain/shared`:

```go
// Define in domain package
type ID = shared.ID

func ParseID(s string) (ID, error) {
    return shared.IDFromString(s)
}

// Usage
id, err := role.ParseID(input.RoleID)
if err != nil {
    return fmt.Errorf("%w: invalid role id format", shared.ErrValidation)
}
```

### Error Handling

Use domain-specific errors and wrap with context:

```go
// Domain errors (in domain/role/errors.go)
var (
    ErrRoleNotFound  = fmt.Errorf("%w: role not found", shared.ErrNotFound)
    ErrRoleInUse     = fmt.Errorf("%w: role is in use", shared.ErrConflict)
    ErrRoleSlugExists = fmt.Errorf("%w: role slug already exists", shared.ErrConflict)
)

// Service layer - wrap with context
if errors.Is(err, role.ErrRoleInUse) {
    return fmt.Errorf("%w: role is assigned to users and cannot be deleted", shared.ErrValidation)
}
return fmt.Errorf("failed to delete role: %w", err)
```

### Repository Pattern

```go
// Interface in domain layer
type Repository interface {
    Create(ctx context.Context, r *Role) error
    GetByID(ctx context.Context, id ID) (*Role, error)
    GetBySlug(ctx context.Context, tenantID *ID, slug string) (*Role, error)
    Delete(ctx context.Context, id ID) error
}

// Implementation in infra/postgres
type RoleRepository struct {
    db *DB
}

func (r *RoleRepository) GetByID(ctx context.Context, id role.ID) (*role.Role, error) {
    // ... implementation
    if errors.Is(err, sql.ErrNoRows) {
        return nil, role.ErrRoleNotFound
    }
    return nil, fmt.Errorf("failed to get role: %w", err)
}
```

**CRITICAL: Tenant-Scoped Isolation**

> **Important:** Every repository function that works with tables containing a `tenant_id` column **MUST** enforce tenant-scoped isolation. This means:
>
> - All queries (SELECT, UPDATE, DELETE) **MUST** include `WHERE tenant_id = ?` clause
> - Never query across tenants without explicit tenant_id filter
> - This prevents data leakage between tenants
> - Applies to all multi-tenant tables (findings, assets, scans, etc.)
>
> **Example:**
>
> ```go
> // ❌ BAD - No tenant isolation
> func (r *FindingRepository) GetByID(ctx context.Context, id ID) (*Finding, error) {
>     query := "SELECT * FROM findings WHERE id = ?"
>     // Missing tenant_id check - can access any tenant's data!
> }
>
> // ✅ GOOD - Tenant-scoped
> func (r *FindingRepository) GetByID(ctx context.Context, tenantID shared.ID, id ID) (*Finding, error) {
>     query := "SELECT * FROM findings WHERE id = ? AND tenant_id = ?"
>     // Safe - only returns findings for specified tenant
> }
> ```

### Database Query Optimization

**CRITICAL PERFORMANCE REQUIREMENT:** All database queries **MUST** be optimized to ensure optimal performance and scalability.

**Why this matters:**

- Poor query performance impacts all users in multi-tenant system
- Database is often the bottleneck in web applications
- Inefficient queries can cause timeouts, high CPU usage, and poor user experience
- Optimization is harder to add later than to build in from the start

**Optimization Rules:**

1. **Use indexes appropriately**
   - Add indexes on frequently queried columns (`tenant_id`, `id`, `created_at`, etc.)
   - Composite indexes for multi-column WHERE clauses: `(tenant_id, created_at)`, `(tenant_id, status)`
   - Avoid over-indexing (slows down writes)

2. **Select only needed columns**
   ```go
   // ❌ BAD
   query := "SELECT * FROM findings WHERE tenant_id = ?"

   // ✅ GOOD
   query := "SELECT id, title, severity, status FROM findings WHERE tenant_id = ?"
   ```

3. **Always paginate large result sets**
   ```go
   // ✅ GOOD - With pagination
   query := `
       SELECT id, title, severity, created_at
       FROM findings
       WHERE tenant_id = ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?
   `
   ```

4. **Avoid N+1 queries**
   ```go
   // ❌ BAD - N+1 query problem
   findings := getFindingsForTenant(tenantID)
   for _, f := range findings {
       asset := getAssetByID(f.AssetID) // N queries!
   }

   // ✅ GOOD - Use JOIN or batch loading
   query := `
       SELECT f.*, a.name as asset_name
       FROM findings f
       LEFT JOIN assets a ON f.asset_id = a.id
       WHERE f.tenant_id = ?
   `
   ```

5. **Optimize WHERE clauses**
   ```go
   // ❌ BAD - Function on indexed column breaks index
   query := "SELECT * FROM findings WHERE LOWER(title) = LOWER(?)"

   // ✅ GOOD - Use case-insensitive operator
   query := "SELECT * FROM findings WHERE title ILIKE ?"
   ```

6. **Use appropriate data types**
   - Use `UUID` for IDs (indexed)
   - Use `TIMESTAMP` for dates
   - Use `JSONB` (not JSON) for JSON data - it's indexed

**Performance Monitoring:**

```bash
# Check query performance
EXPLAIN ANALYZE SELECT ...

# Monitor slow queries in production
# Set in postgresql.conf:
# log_min_duration_statement = 1000  # Log queries > 1s
```

**Index Management:**

- Create indexes in migrations, not in queries
- Use `CREATE INDEX CONCURRENTLY` to avoid locking tables
- Monitor index usage: `pg_stat_user_indexes`
- Drop unused indexes to improve write performance

**Key Files:**

- `api/migrations/*.sql` - Database indexes
- `api/internal/infra/postgres/*_repository.go` - Query implementations

### Cache Usage Guidelines

**CRITICAL:** Caching improves performance but introduces complexity. Use caching strategically and always have a clear invalidation strategy.

**When to use cache:**

✅ **Good use cases:**
- User sessions and permissions (5-30 minutes TTL)
- Configuration data (1-24 hours)
- Expensive query results (1-60 minutes)
- Reference data (lookup tables, enums)
- Rate limiting counters

❌ **Avoid caching:**
- Real-time data (findings, scans in progress)
- Large objects (> 1MB)
- Sensitive data without encryption
- Data where staleness causes critical issues

**Redis Cache Patterns:**

```go
// Pattern 1: Cache-Aside (Lazy Loading)
func (s *FindingService) GetByID(ctx context.Context, id shared.ID) (*Finding, error) {
    // Try cache first
    cacheKey := fmt.Sprintf("finding:%s", id)
    cached, err := s.redis.Get(ctx, cacheKey).Result()
    if err == nil {
        return deserialize(cached), nil
    }

    // Cache miss - query database
    finding, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }

    // Store in cache with TTL
    s.redis.Set(ctx, cacheKey, serialize(finding), 5*time.Minute)
    return finding, nil
}

// Pattern 2: Write-Through (Update cache on write)
func (s *UserService) UpdateUser(ctx context.Context, user *User) error {
    // Update database first
    err := s.repo.Update(ctx, user)
    if err != nil {
        return err
    }

    // Update cache immediately
    cacheKey := fmt.Sprintf("user:%s", user.ID)
    s.redis.Set(ctx, cacheKey, serialize(user), 30*time.Minute)

    return nil
}

// Pattern 3: Cache Invalidation on Write
func (s *RoleService) UpdateRole(ctx context.Context, role *Role) error {
    err := s.repo.Update(ctx, role)
    if err != nil {
        return err
    }

    // Invalidate all user permissions cache (they may have this role)
    s.redis.Del(ctx, "user:permissions:*")

    return nil
}
```

**Common Pitfalls:**

1. **Cache Stampede** - Multiple requests hit database when cache expires
   ```go
   // ✅ GOOD - Use golang.org/x/sync/singleflight
   var group singleflight.Group

   result, err, _ := group.Do(key, func() (interface{}, error) {
       return fetchFromDB(id)
   })
   ```

2. **Stale Data** - Cache not invalidated on updates
   ```go
   // ✅ GOOD - Always invalidate on write
   func (s *Service) Update(ctx context.Context, data *Data) error {
       err := s.repo.Update(ctx, data)
       s.redis.Del(ctx, "data:"+data.ID) // Invalidate!
       return err
   }
   ```

3. **Cache Key Collisions** - No tenant isolation in keys
   ```go
   // ❌ BAD
   key := fmt.Sprintf("finding:%s", findingID)

   // ✅ GOOD - Include tenant in cache key
   key := fmt.Sprintf("tenant:%s:finding:%s", tenantID, findingID)
   ```

4. **No TTL** - Cache grows indefinitely
   ```go
   // ❌ BAD
   redis.Set(ctx, key, value, 0) // No TTL!

   // ✅ GOOD - Always set TTL
   redis.Set(ctx, key, value, 10*time.Minute)
   ```

**Cache Invalidation Strategies:**

```go
// 1. Direct invalidation
redis.Del(ctx, "user:123")

// 2. Pattern-based invalidation (expensive!)
keys := redis.Keys(ctx, "tenant:*:findings:*").Val()
redis.Del(ctx, keys...)

// 3. Cache versioning (recommended for breaking changes)
type CachedData struct {
    Version int    `json:"v"`
    Data    []byte `json:"d"`
}
// When schema changes, increment version in code
// Old cached data with wrong version is ignored
```

**TTL Recommendations:**

| Data Type | TTL | Notes |
|-----------|-----|-------|
| User permissions | 5 min | Invalidate on role change |
| User sessions | 30 min | Standard session timeout |
| Configuration | 1 hour | Rarely changes |
| Query results | 1-5 min | Balance freshness vs load |
| Rate limits | 1 min | Short window |

**Performance Monitoring:**

```go
// Track metrics
cache_hits_total
cache_misses_total
cache_evictions_total

// Monitor hit ratio
hit_ratio = hits / (hits + misses)
// Target: > 80% hit ratio
```

**Key Files:**

- `api/internal/infra/redis/` - Redis clients
- `api/internal/app/permission_version_service.go` - Permission cache versioning
- `api/internal/app/session_service.go` - Session caching

### Advanced Cache Edge Cases & Pain Points

**Based on real-world production experience.** These are the issues that will bite you in production:

#### 1. **Distributed Cache Invalidation (Multi-Server Problem)**

**Problem:** You have 3 API servers. Server A updates user data and invalidates local cache. Servers B & C still have stale data.

```go
// ❌ PROBLEM - Only invalidates local server's cache
func (s *UserService) UpdateUser(ctx context.Context, user *User) error {
    s.repo.Update(ctx, user)
    s.localCache.Delete(user.ID) // Only THIS server knows!
    return nil
}

// ✅ SOLUTION - Use Redis for shared cache
func (s *UserService) UpdateUser(ctx context.Context, user *User) error {
    s.repo.Update(ctx, user)
    s.redis.Del(ctx, "user:"+user.ID) // All servers see this

    // OR: Publish invalidation event via Redis Pub/Sub
    s.redis.Publish(ctx, "cache:invalidate", "user:"+user.ID)
    return nil
}
```

**Lesson:** Never use in-memory cache for mutable data in multi-server environments.

#### 2. **Cache Poisoning (Bad Data Gets Cached)**

**Problem:** Validation fails AFTER caching, or corrupted data gets cached.

```go
// ❌ PROBLEM - Cache before validation
func GetUser(id string) (*User, error) {
    if cached := cache.Get(id); cached != nil {
        return cached, nil // What if cached data is corrupted?
    }

    user := db.Query(id)
    cache.Set(id, user) // Cached BEFORE validation!

    if user.IsDeleted {
        return nil, ErrNotFound // Too late! Already cached
    }
    return user, nil
}

// ✅ SOLUTION - Validate before caching
func GetUser(id string) (*User, error) {
    if cached := cache.Get(id); cached != nil {
        if err := validate(cached); err != nil {
            cache.Del(id) // Invalidate bad cache
        } else {
            return cached, nil
        }
    }

    user := db.Query(id)

    // Validate BEFORE caching
    if user.IsDeleted {
        return nil, ErrNotFound
    }

    if err := validate(user); err != nil {
        return nil, err // Don't cache invalid data
    }

    cache.Set(id, user)
    return user, nil
}
```

#### 3. **Race Conditions (Read-Modify-Write)**

**Problem:** Two requests read cached counter, increment it, both write back wrong value.

```go
// ❌ PROBLEM - Race condition
func IncrementCounter(userID string) error {
    count := cache.Get("counter:"+userID) // Both read "5"
    count++                                 // Both compute "6"
    cache.Set("counter:"+userID, count)    // Both write "6" (should be 7!)
    return nil
}

// ✅ SOLUTION - Use atomic operations
func IncrementCounter(userID string) error {
    // Redis INCR is atomic
    _, err := redis.Incr(ctx, "counter:"+userID).Result()
    return err
}

// For complex updates, use optimistic locking
func UpdateUserBalance(userID string, amount int) error {
    for {
        // Get with version
        cached := cache.Get("user:"+userID)
        user, version := deserialize(cached)

        user.Balance += amount

        // Only update if version matches (optimistic lock)
        success := cache.SetNX("user:"+userID, serialize(user, version+1))
        if success {
            return nil
        }
        // Retry if version changed
    }
}
```

#### 4. **TTL Synchronization (Cascading Expiration)**

**Problem:** User data expires but their permissions cache doesn't.

```go
// ❌ PROBLEM - Mismatched TTLs
cache.Set("user:123", userData, 5*time.Minute)
cache.Set("user:123:permissions", perms, 30*time.Minute) // Stale perms!

// ✅ SOLUTION - Synchronized TTLs or dependency tracking
func CacheUserWithPermissions(user *User) {
    ttl := 10 * time.Minute

    // Same TTL for related data
    cache.Set("user:"+user.ID, user, ttl)
    cache.Set("user:"+user.ID+":permissions", user.Permissions, ttl)

    // OR: Store dependencies
    cache.Set("user:"+user.ID+":deps", []string{
        "user:"+user.ID+":permissions",
        "user:"+user.ID+":settings",
    }, ttl)
}

// On invalidation, clear all dependencies
func InvalidateUser(userID string) {
    deps := cache.Get("user:"+userID+":deps")
    for _, key := range deps {
        cache.Del(key)
    }
    cache.Del("user:" + userID)
}
```

#### 5. **Partial Cache Failures (Redis Downtime)**

**Problem:** Redis dies, your app crashes because it doesn't handle cache failures.

```go
// ❌ PROBLEM - App fails when cache fails
func GetUser(id string) (*User, error) {
    cached := cache.Get(id) // Panics if Redis is down!
    if cached != nil {
        return cached, nil
    }
    return db.Query(id)
}

// ✅ SOLUTION - Graceful degradation
func GetUser(id string) (*User, error) {
    // Try cache, but don't fail if unavailable
    cached, err := cache.Get(id)
    if err == nil && cached != nil {
        return cached, nil
    }

    // Log cache failure but continue
    if err != nil {
        log.Warn("cache unavailable", "error", err)
        metrics.IncrCacheMisses()
    }

    // Fallback to database
    user, err := db.Query(id)
    if err != nil {
        return nil, err
    }

    // Try to cache result (best effort)
    _ = cache.Set(id, user) // Ignore cache errors

    return user, nil
}
```

#### 6. **Negative Caching (Caching "Not Found")**

**Problem:** Keep querying DB for non-existent data.

```go
// ❌ PROBLEM - No negative caching
func GetUser(id string) (*User, error) {
    if cached := cache.Get(id); cached != nil {
        return cached, nil
    }

    user := db.Query(id)
    if user == nil {
        return nil, ErrNotFound // Queried DB again next time!
    }

    cache.Set(id, user)
    return user, nil
}

// ✅ SOLUTION - Cache "not found" with short TTL
const NotFoundSentinel = "NOT_FOUND"

func GetUser(id string) (*User, error) {
    cached := cache.Get("user:" + id)

    if cached == NotFoundSentinel {
        return nil, ErrNotFound // Cached negative result
    }

    if cached != nil {
        return deserialize(cached), nil
    }

    user := db.Query(id)
    if user == nil {
        // Cache "not found" with SHORT TTL (1 minute)
        cache.Set("user:"+id, NotFoundSentinel, 1*time.Minute)
        return nil, ErrNotFound
    }

    cache.Set("user:"+id, user, 10*time.Minute)
    return user, nil
}
```

#### 7. **Cache Key Collisions (Namespace Issues)**

**Problem:** Different entities with same ID collide.

```go
// ❌ PROBLEM - Key collision
cache.Set("123", userData)    // User with ID 123
cache.Set("123", productData) // Product with ID 123 - COLLISION!

// ✅ SOLUTION - Structured key naming
func CacheKey(entity string, tenantID, id string) string {
    return fmt.Sprintf("%s:%s:%s", entity, tenantID, id)
}

cache.Set(CacheKey("user", tenantID, "123"), userData)
cache.Set(CacheKey("product", tenantID, "123"), productData)

// Even better: Use a key builder
type CacheKeyBuilder struct {
    tenant string
}

func (b *CacheKeyBuilder) User(id string) string {
    return fmt.Sprintf("t:%s:user:%s", b.tenant, id)
}

func (b *CacheKeyBuilder) Product(id string) string {
    return fmt.Sprintf("t:%s:product:%s", b.tenant, id)
}
```

#### 8. **Serialization Versioning (Schema Changes)**

**Problem:** Code deploys with new User struct, old cached data has different fields.

```go
// ❌ PROBLEM - Schema mismatch
type User struct {
    ID    string
    Name  string
    Email string // NEW FIELD - breaks old cached data!
}

// ✅ SOLUTION - Versioned cache with migration
type CachedUser struct {
    Version int         `json:"v"`
    Data    interface{} `json:"d"`
}

const CurrentUserCacheVersion = 2

func CacheUser(user *User) {
    cached := CachedUser{
        Version: CurrentUserCacheVersion,
        Data:    user,
    }
    cache.Set("user:"+user.ID, cached, 10*time.Minute)
}

func GetCachedUser(id string) (*User, error) {
    cached := cache.Get("user:" + id)

    if cached.Version != CurrentUserCacheVersion {
        // Old cache format - invalidate and fetch fresh
        cache.Del("user:" + id)
        return nil, ErrCacheMiss
    }

    return cached.Data.(*User), nil
}
```

#### 9. **Cache Warming Race Conditions**

**Problem:** App starts, 1000 requests all try to warm the same cache key.

```go
// ❌ PROBLEM - Cache warming stampede
func WarmCache() {
    for _, id := range popularUserIDs {
        go func(id string) {
            user := db.Query(id) // 1000 goroutines hit DB!
            cache.Set("user:"+id, user)
        }(id)
    }
}

// ✅ SOLUTION - Controlled cache warming
func WarmCache() {
    // Limit concurrency
    sem := make(chan struct{}, 10) // Max 10 concurrent

    for _, id := range popularUserIDs {
        sem <- struct{}{} // Acquire

        go func(id string) {
            defer func() { <-sem }() // Release

            // Check if already cached
            if cache.Exists("user:" + id) {
                return
            }

            user := db.Query(id)
            cache.Set("user:"+id, user)

            time.Sleep(10 * time.Millisecond) // Rate limit
        }(id)
    }
}
```

#### 10. **Multi-Tenant Cache Leaks (Critical Security Issue)**

**Problem:** Tenant A can access Tenant B's cached data.

```go
// ❌ CRITICAL BUG - No tenant isolation
func GetFindings(userID string) ([]Finding, error) {
    key := "findings:" + userID // WRONG! No tenant ID
    return cache.Get(key)
}

// User switches tenant, sees old tenant's data!

// ✅ SOLUTION - Always include tenant in key
func GetFindings(tenantID, userID string) ([]Finding, error) {
    key := fmt.Sprintf("t:%s:findings:%s", tenantID, userID)

    cached := cache.Get(key)
    if cached != nil {
        // Double-check tenant matches (defense in depth)
        for _, f := range cached {
            if f.TenantID != tenantID {
                log.Error("CACHE LEAK DETECTED", "key", key)
                cache.Del(key)
                return nil, ErrCacheCorrupted
            }
        }
        return cached, nil
    }

    findings := db.Query(tenantID, userID)
    cache.Set(key, findings)
    return findings, nil
}
```

#### 11. **Memory Bloat (Cache Growing Unbounded)**

**Problem:** Cache keeps growing until Redis runs out of memory.

```bash
# ✅ SOLUTION - Configure Redis eviction policy
# In redis.conf:
maxmemory 2gb
maxmemory-policy allkeys-lru  # Evict least recently used keys

# Monitor memory usage
redis-cli INFO memory
```

```go
// Also: Set TTL on EVERYTHING
func CacheSet(key string, value interface{}) {
    // ❌ NEVER do this
    // redis.Set(ctx, key, value, 0) // No TTL = memory leak!

    // ✅ Always set TTL
    ttl := determineTTL(key) // 1 min to 24 hours based on data type
    redis.Set(ctx, key, value, ttl)
}
```

**Production Monitoring Checklist:**

- [ ] Cache hit ratio (target > 80%)
- [ ] Cache memory usage (set alerts at 70%, 90%)
- [ ] Cache eviction rate (high = cache too small)
- [ ] Cache operation latency (p50, p99)
- [ ] Failed cache operations (Redis timeouts, connection errors)
- [ ] Cache key distribution (detect hot keys)
- [ ] TTL mismatches (related data with different TTLs)

## Running Lint

```bash
# Run linter
GOWORK=off golangci-lint run ./...

# Auto-fix some issues
GOWORK=off golangci-lint run ./... --fix

# Format code
goimports -w ./...
```

## Common Commands

See [`docs/MAKEFILE.md`](./docs/MAKEFILE.md) for complete command reference.

```bash
# Run server
make run

# Run with hot reload
make dev

# Run tests
make test

# Run migrations
make migrate-up

# Generate mocks
make mocks

# Generate encryption key (for APP_ENCRYPTION_KEY)
openssl rand -hex 32
```

## Credentials Encryption

Integration credentials (access tokens, API keys) are encrypted using AES-256-GCM.

**Configuration:**

- `APP_ENCRYPTION_KEY`: 32-byte key (required in production)
  - Hex format: 64 characters (`openssl rand -hex 32`)
  - Base64 format: 44 characters (`openssl rand -base64 32`)
  - Raw format: 32 bytes

**Behavior:**

- If `APP_ENCRYPTION_KEY` is not set, credentials are stored in plaintext (dev only)
- In production (`APP_ENV=production`), the key is required
- Existing plaintext credentials remain readable (backward compatible)

## Audit Logging

Use the audit service for logging important actions:

```go
event := NewSuccessEvent(audit.ActionRoleCreated, audit.ResourceTypeRole, r.ID().String()).
    WithResourceName(r.Name()).
    WithMessage(fmt.Sprintf("Role '%s' created", r.Name())).
    WithMetadata("slug", r.Slug()).
    WithSeverity(audit.SeverityMedium)
s.logAudit(ctx, actx, event)
```

## 3-Layer Access Control

OpenCTEM implements a 3-layer access control architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 1: LICENSING (Tenant)                   │
├─────────────────────────────────────────────────────────────────┤
│  Tenant → Plan → Modules                                        │
│  "What modules can this tenant access?"                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 2: RBAC (User)                          │
├─────────────────────────────────────────────────────────────────┤
│  User → Roles → Permissions                                      │
│  "What can this user do within allowed modules?"                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 3: DATA SCOPE (Groups)                  │
├─────────────────────────────────────────────────────────────────┤
│  User → Groups → Assets/Data                                     │
│  "What data can this user see?"                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1: Licensing

**Key Files:**

- `internal/domain/licensing/` - Domain models (Plan, Module, Subscription)
- `internal/infra/postgres/licensing_repository.go` - Repository
- `internal/app/licensing_service.go` - Business logic
- `internal/infra/http/handler/licensing_handler.go` - HTTP handler

**API Endpoints:**

```
GET /api/v1/plans              # List public plans
GET /api/v1/plans/{id}         # Get plan details
GET /api/v1/modules            # List active modules
GET /api/v1/me/modules         # Get tenant's enabled modules
GET /api/v1/me/subscription    # Get tenant's subscription
```

**Usage:**

```go
// Check module access
hasModule, err := licensingService.TenantHasModule(ctx, tenantID, "findings")

// Get enabled modules
output, err := licensingService.GetTenantEnabledModules(ctx, tenantID)
moduleIDs := output.ModuleIDs  // ["dashboard", "assets", "findings"]

// Get available event types for notifications (based on modules)
eventTypes, err := licensingService.GetTenantAvailableEventTypes(ctx, tenantID)
```

**Module Middleware (JWT Routes):**

```go
// For JWT-authenticated routes (tenant ID from token)
middleware.RequireModule(licensingService, licensing.ModuleAssets)
```

**Module Middleware (Agent Routes):**

```go
// For API key-authenticated routes (tenant ID from agent)
agentProvider := middleware.AgentContextProviderFunc(handler.AgentFromContext)
middleware.RequireModuleForAgent(licensingService, agentProvider, licensing.ModuleScans)
```

**Agent Route Module Requirements:**
| Endpoint | Module | Notes |
|----------|--------|-------|
| `POST /api/v1/agent/heartbeat` | None | Always allowed |
| `POST /api/v1/agent/ingest` | `scans` | Finding/asset ingestion |
| `POST /api/v1/agent/ingest/sarif` | `scans` | SARIF ingestion |
| `GET /api/v1/agent/commands` | `scans` | Command polling |
| `POST /api/v1/agent/credentials/ingest` | `credentials` | Credential ingestion |

**Agent Management Module Requirements:**
| Endpoint | Module | Notes |
|----------|--------|-------|
| `GET /api/v1/agents` | `scans` | List agents |
| `POST /api/v1/agents` | `scans` | Create agent (limited by plan's agent_limit) |
| `PUT /api/v1/agents/{id}` | `scans` | Update agent |
| `DELETE /api/v1/agents/{id}` | `scans` | Delete agent |

> **Note:** Agents are bundled with the `scans` module because scanning requires agents to execute.
> The number of agents a tenant can create is controlled by their plan's `agent_limit` field.

### Layer 2: RBAC

**Key Files:**

- `internal/domain/role/` - Role entity with permissions
- `internal/domain/permission/` - Permission constants
- `internal/app/role_service.go` - Role management
- `internal/infra/http/middleware/` - Permission middleware

**Permission Middleware:**

```go
// Single permission check
middleware.Require(permission.AssetsWrite)

// Any of multiple permissions (OR)
middleware.RequireAny(permission.AssetsRead, permission.RepositoriesRead)

// All permissions required (AND)
middleware.RequireAll(permission.AssetsWrite, permission.RepositoriesWrite)

// Admin check (owner or admin role)
middleware.RequireAdmin()

// Owner-only check (for sensitive operations)
middleware.RequireOwner()
```

**Permission Check Flow:**

- **Owner/Admin** (`isAdmin=true` in JWT): Bypass all permission checks
- **Member/Viewer** (`isAdmin=false`): Check permissions array in JWT

**Owner-only Operations** (use `RequireOwner()`):

- `TeamDelete` - Delete tenant
- `BillingManage` - Manage billing
- `GroupsDelete`, `PermissionSetsDelete`, `AssignmentRulesDelete`

**Route Registration:**

```go
r.Route("/assets", func(r chi.Router) {
    r.With(middleware.Require(permission.AssetsRead)).Get("/", h.List)
    r.With(middleware.Require(permission.AssetsWrite)).Post("/", h.Create)
    r.With(middleware.Require(permission.AssetsDelete)).Delete("/{id}", h.Delete)
})
```

### Layer 3: Data Scope (Groups)

**Key Files:**

- `internal/domain/group/` - Group entity
- `internal/app/group_service.go` - Group management
- `internal/infra/http/handler/group_handler.go` - HTTP handler

**Usage:**

```go
// Users can only see data from their groups
// Data filtering happens at query level based on group membership
```

### Permission Check Flow

```
Request with JWT Token
    ↓
UnifiedAuth Middleware
├─ Validate Token (Local JWT or OIDC)
├─ Extract user_id, tenant_id, permissions
└─ Set context values
    ↓
Permission Middleware (middleware.Require)
├─ Local Auth: Check permissions[] from JWT
└─ OIDC Auth: Check roles from claims
    ↓
If ✓ → Handler executes
If ✗ → 403 Forbidden
```

### Membership Levels

| Level      | Description                                   |
| ---------- | --------------------------------------------- |
| **Owner**  | Full access to everything. Cannot be removed. |
| **Member** | Permissions from RBAC roles only.             |

**Note:** Owner has ALL permissions regardless of roles assigned.

### Permission Real-time Sync

**Important Architecture Decision:** Permissions are synchronized in real-time when admin revokes/grants access.

See [`docs/architecture/permission-realtime-sync.md`](../docs/architecture/permission-realtime-sync.md) for complete implementation guide.

**Key Points:**

- JWT contains only `perm_version` (not full permissions array)
- Permissions stored in Redis/localStorage for quick access
- `X-Permission-Stale` header signals frontend when version mismatch
- Multiple triggers: stale header, 403 error, tab focus, polling interval

**Version Tracking:**

```go
// Redis keys
perm_ver:{tenant_id}:{user_id}    // Current version (TTL: 30 days)
user_perms:{tenant_id}:{user_id}  // Cached permissions (TTL: 5 minutes)

// Increment version when roles change
permVersionService.Increment(ctx, tenantID, userID)
```

**Cache Invalidation Triggers:**

| Event                          | Cache Action              | Version Action           | Service          |
| ------------------------------ | ------------------------- | ------------------------ | ---------------- |
| Role assigned/removed          | Clear user cache          | Increment version        | `RoleService`    |
| Role permissions changed       | Clear all users with role | Increment affected users | `RoleService`    |
| **Member removed from tenant** | Clear user cache          | **Delete version**       | `TenantService`  |
| **Session revoked**            | Clear all tenants cache   | No change                | `SessionService` |
| **User suspended**             | Clear via session revoke  | No change                | `UserService`    |

**Important Security Guarantees:**

1. **Member removed from tenant:**
   - `user_roles` deleted from DB (no permissions)
   - Permission cache cleared immediately
   - Permission version deleted
   - **Window: 0 seconds**

2. **Session revoked (logout all devices):**
   - All sessions marked as revoked
   - Refresh tokens revoked
   - Permission cache cleared for ALL tenants user belongs to
   - **Window: 0 seconds**

3. **User suspended:**
   - User status set to "suspended"
   - All sessions revoked immediately
   - Cannot re-login until activated
   - **Window: 0 seconds**

## Notification System

Multi-channel notification system supporting Slack, Teams, Telegram, Email, and custom webhooks.

### Architecture

```
internal/
├── domain/
│   ├── integration/
│   │   ├── notification_extension.go   # NotificationExtension entity, EventType
│   │   └── repository.go               # Repository interfaces
│   └── notification/
│       ├── outbox.go                   # Outbox entity (transient queue)
│       ├── event.go                    # Event entity (permanent archive)
│       ├── repository.go               # Repository interfaces
│       └── errors.go                   # Domain errors
├── infra/
│   ├── notification/               # Notification clients
│   │   ├── client.go              # Client interface & factory
│   │   ├── slack.go               # Slack webhook client
│   │   ├── teams.go               # Microsoft Teams client
│   │   ├── telegram.go            # Telegram bot client
│   │   ├── webhook.go             # Generic webhook client
│   │   └── email.go               # SMTP email client
│   └── postgres/
│       ├── notification_outbox_repository.go
│       ├── notification_event_repository.go
│       └── integration_notification_extension_repository.go
└── app/
    ├── notification_service.go      # Processing logic
    └── notification_scheduler.go    # Polling scheduler
```

### Key Concepts

**Event Types (Dynamic JSONB):**

```go
// Domain types - can add new types without migration
type EventType string

const (
    EventTypeFindings  EventType = "findings"
    EventTypeExposures EventType = "exposures"
    EventTypeScans     EventType = "scans"
    EventTypeAlerts    EventType = "alerts"
)

// Stored as JSONB array: ["findings", "exposures", "alerts"]
// Empty array = all events enabled (backward compatible)
```

**Notification Extension:**

```go
type NotificationExtension struct {
    integrationID        ID
    enabledSeverities    []Severity    // Severity filters (replaces notify_on_* booleans)
    enabledEventTypes    []EventType   // Dynamic event routing
    messageTemplate      string        // Custom template with {title}, {severity}, {url}, {body}
    includeDetails       bool
    minIntervalMinutes   int           // Rate limiting
}
// Note: Provider-specific config (chat_id, channel_name, smtp_host, etc.) is now stored
// in Integration.Metadata (non-sensitive) and Integration.CredentialsEncrypted (sensitive)
```

**Broadcast Pattern:**

```go
// Send notification to all matching channels
input := BroadcastNotificationInput{
    TenantID:  tenantID,
    EventType: integration.EventTypeFindings,  // Route by event type
    Title:     "Critical Vulnerability Found",
    Body:      "SQL Injection in login endpoint",
    Severity:  "critical",                     // Filter by severity
    URL:       "https://app.example.com/finding/123",
}
results, err := service.BroadcastNotification(ctx, input)
```

### Rate Limiting

Test notification endpoint has rate limiting (5 requests/minute per user+integration):

```go
// In handler
type testNotificationRateLimiter struct {
    mu       sync.Mutex
    requests map[string][]time.Time  // key: "userID:integrationID"
    limit    int                     // 5
    window   time.Duration           // 1 minute
}

// Returns 429 Too Many Requests with Retry-After header
```

### Adding New Event Types

1. Add constant in `domain/integration/notification_extension.go`:

```go
const EventTypeNewType EventType = "new_type"
```

2. Update `AllKnownEventTypes()` for UI display
3. No migration needed - JSONB stores any string values

### Adding New Notification Provider

1. Create client in `internal/infra/notification/`:

```go
type NewProviderClient struct {
    config Config
}

func (c *NewProviderClient) Send(ctx context.Context, msg Message) (*SendResult, error)
func (c *NewProviderClient) TestConnection(ctx context.Context) (*SendResult, error)
func (c *NewProviderClient) Provider() string { return "new_provider" }
```

2. Register in factory (`client.go`):

```go
case ProviderNewProvider:
    return NewNewProviderClient(cfg)
```

3. Add provider constant and update validation

### Notification Outbox (Transactional Pattern)

The system uses the **Transactional Outbox Pattern** for reliable notification delivery:

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

**Key Files:**

- `internal/domain/notification/outbox.go` - Outbox entity
- `internal/domain/notification/repository.go` - Repository interface
- `internal/infra/postgres/notification_outbox_repository.go` - PostgreSQL implementation
- `internal/app/notification_service.go` - Processing logic
- `internal/app/notification_scheduler.go` - Polling scheduler
- `internal/infra/http/handler/notification_outbox_handler.go` - Tenant API

**Outbox Status Lifecycle:**

```
pending → processing → [ARCHIVE to notification_events] → [DELETE from outbox]
                    ↳ failed (retries with exponential backoff)
                           ↳ dead (manual intervention required)
```

**Event Status (notification_events):**

- `completed`: At least one integration succeeded
- `failed`: All integrations failed after retries
- `skipped`: No integrations matched filters

**Retention:**

- `notification_outbox`: 7 days (failed), most entries deleted immediately after archive
- `notification_events`: 90 days (configurable via EventRetentionDays)

**Tenant API Endpoints:**

> **Note**: This API is tenant-scoped. Tenants can only view and manage their own notifications.

```
GET  /api/v1/notification-outbox          # List entries (tenant-scoped)
GET  /api/v1/notification-outbox/stats    # Get statistics (tenant-scoped)
GET  /api/v1/notification-outbox/{id}     # Get single entry (must belong to tenant)
POST /api/v1/notification-outbox/{id}/retry # Retry failed entry (must belong to tenant)
DELETE /api/v1/notification-outbox/{id}   # Delete entry (must belong to tenant)
```

**Permissions Required:**

- `integrations:notifications:read` for GET endpoints
- `integrations:notifications:write` for POST (retry)
- `integrations:notifications:delete` for DELETE

**Usage in Services:**

```go
// In vulnerability_service.go or similar
tx, err := s.db.BeginTx(ctx, nil)
defer tx.Rollback()

// Create business entity in transaction
finding, err := s.findingRepo.CreateInTx(ctx, tx, finding)

// Enqueue notification in SAME transaction
err = s.notificationService.EnqueueNotificationInTx(ctx, tx, app.EnqueueNotificationParams{
    TenantID:      tenantID,
    EventType:     "new_finding",
    AggregateType: "finding",
    AggregateID:   &finding.ID,
    Title:         fmt.Sprintf("New %s Finding: %s", finding.Severity, finding.Title),
    Severity:      finding.Severity.String(),
})

return tx.Commit()  // Both or neither succeed
```

For detailed documentation, see `docs/architecture/notification-system.md`.

## MANDATORY: Code Quality Checks

**IMPORTANT: After completing any code changes, ALWAYS run these checks before committing:**

```bash
# 1. Run linter - MUST pass with no errors
GOWORK=off golangci-lint run ./...

# 2. Format code
goimports -w ./...

# 3. Run tests (if applicable)
make test
```

**Common issues to watch for:**

- `errorlint`: Always use `errors.Is()` for error comparison
- `prealloc`: Pre-allocate slices when capacity is known
- `goconst`: Use constants for repeated strings
- `errcheck`: Check error returns, especially in defer
- `goimports`: Keep imports properly formatted

**Pre-commit hooks will fail if linting errors exist.**

## Platform Agents Architecture (v3.2)

Platform Agents are OpenCTEM-managed agents running on OpenCTEM infrastructure, shared across all tenants. Supports users who cannot deploy their own agents.

### Key Components

**1. Platform Agent Entity** (`internal/domain/agent/entity.go`):

- `IsPlatformAgent bool` - Distinguishes platform agents from tenant agents
- `PlatformAgentStats` - Aggregate statistics for platform agents
- `PlatformAgentSelectionRequest` - Request for agent selection

**2. Bootstrap Token** (`internal/domain/agent/bootstrap_token.go`):

- Kubeadm-style tokens for agent self-registration
- Usage limits, expiration, constraints validation
- Audit logging via `AgentRegistration`

**3. Queue Management**:

- Weighted Fair Queuing with age bonus
- `FOR UPDATE SKIP LOCKED` for concurrent safety
- Automatic stuck job recovery

### Database Schema

```sql
-- Platform agent columns (agents table)
is_platform_agent BOOLEAN DEFAULT FALSE
current_jobs INTEGER DEFAULT 0
max_concurrent_jobs INTEGER DEFAULT 5

-- Queue columns (commands table)
is_platform_job BOOLEAN DEFAULT FALSE
platform_agent_id UUID
auth_token_hash TEXT
queue_priority INTEGER DEFAULT 0
queued_at TIMESTAMP

-- Bootstrap tokens table
bootstrap_tokens (id, token_hash, expires_at, max_uses, required_capabilities...)
agent_registrations (id, agent_id, bootstrap_token_id, registered_at...)
```

### Key Files

```
internal/
├── domain/
│   ├── agent/
│   │   ├── entity.go          # PlatformAgentStats, selection structs
│   │   ├── bootstrap_token.go # Bootstrap token entity
│   │   ├── errors.go          # Platform agent errors
│   │   └── repository.go      # Platform agent interfaces
│   ├── lease/
│   │   ├── entity.go          # K8s-style lease entity
│   │   ├── errors.go          # Lease-specific errors
│   │   └── repository.go      # Lease interface
│   └── admin/
│       ├── entity.go          # AdminUser entity (super_admin, ops_admin, readonly)
│       ├── errors.go          # Admin errors
│       └── repository.go      # Admin interface
├── infra/
│   ├── postgres/
│   │   ├── agent_repository.go           # Platform agent methods
│   │   ├── bootstrap_token_repository.go # Bootstrap token repo
│   │   ├── lease_repository.go           # Lease repo with atomic ops
│   │   └── admin_repository.go           # Admin user repo
│   ├── controller/
│   │   ├── controller.go      # Controller orchestration
│   │   ├── agent_health.go    # Lease expiry checking
│   │   ├── job_recovery.go    # Stuck job recovery
│   │   ├── queue_priority.go  # WFQ priority updates
│   │   ├── token_cleanup.go   # Expired token cleanup
│   │   └── audit_retention.go # Admin audit log retention
│   └── http/
│       ├── handler/
│       │   ├── platform_handler.go          # Lease & poll endpoints
│       │   ├── platform_register_handler.go # Agent self-registration
│       │   ├── platform_agent_handler.go    # Agent management
│       │   └── platform_job_handler.go      # Job submission & status
│       ├── middleware/
│       │   ├── platform_auth.go  # Platform agent auth
│       │   ├── admin_auth.go     # Admin auth
│       │   └── ratelimit.go      # Registration rate limiting
│       └── routes/
│           └── platform.go       # All platform routes
└── app/
    ├── platform_agent_service.go  # Agent business logic
    └── lease_service.go           # Lease business logic
```

### API Endpoints

**Agent Registration (Public, Rate Limited):**

```
POST /api/v1/platform/register         # Self-registration with bootstrap token
POST /api/v1/platform-agents/register  # Alternative registration endpoint
```

**Agent Communication (API Key Auth):**

```
PUT    /api/v1/platform/lease              # Renew lease (heartbeat)
DELETE /api/v1/platform/lease              # Release lease (graceful shutdown)
POST   /api/v1/platform/poll               # Long-poll for jobs
POST   /api/v1/platform/jobs/{id}/ack      # Acknowledge job receipt
POST   /api/v1/platform/jobs/{id}/result   # Report job result
POST   /api/v1/platform/jobs/{id}/progress # Report job progress
```

**Tenant Job Submission (JWT Auth):**

```
POST /api/v1/platform-jobs/           # Submit job
GET  /api/v1/platform-jobs/           # List jobs
GET  /api/v1/platform-jobs/{id}       # Get job status
POST /api/v1/platform-jobs/{id}/cancel # Cancel job
```

### Implementation Status

| Phase                            | Status      | Notes                              |
| -------------------------------- | ----------- | ---------------------------------- |
| Phase 0: Database Schema         | ✅ Complete | migrations/000080-000083           |
| Phase 1: Domain Layer            | ✅ Complete | agent, lease, admin domains        |
| Phase 2: Infrastructure Layer    | ✅ Complete | All repositories implemented       |
| Phase 3: Application Services    | ✅ Complete | LeaseService, PlatformAgentService |
| Phase 4: HTTP Handlers           | ✅ Complete | All endpoints wired                |
| Phase 5: Routes & Main.go        | ✅ Complete | Routes registered, DI wired        |
| Phase 6: Background Controllers  | ✅ Complete | Health, recovery, cleanup workers  |
| Phase 7: Admin CLI               | 🔄 Pending  |                                    |
| Phase 8: Testing & Documentation | 🔄 Pending  |                                    |

---

---

## Security Checklist (Bắt buộc cho public endpoints)

### 1. Rate Limiting cho Public Endpoints

**Mọi public endpoint (không yêu cầu auth) PHẢI có rate limiting:**

```go
// BAD - Public endpoint without rate limiting
router.Group("/api/v1/platform", func(r Router) {
    r.POST("/register", registerHandler.Register) // ❌ No rate limiting
})

// GOOD - Apply rate limiting middleware
router.Group("/api/v1/platform", func(r Router) {
    r.POST("/register", registerHandler.Register)
}, middleware.RateLimit(10, time.Minute)) // ✅ 10 req/min per IP
```

### 2. Generic Error Messages (Tránh Information Disclosure)

**KHÔNG BAO GIỜ expose trạng thái nội bộ qua error messages:**

```go
// BAD - Leaks token state (expired, exhausted, revoked)
if err := token.CanBeUsed(); err != nil {
    apierror.Unauthorized("bootstrap token is not usable: " + err.Error()).WriteJSON(w)
}

// GOOD - Generic error, log details internally
if err := token.CanBeUsed(); err != nil {
    apierror.Unauthorized("Invalid or expired token").WriteJSON(w)
    h.logger.Warn("token validation failed", "reason", err.Error()) // Log chi tiết
}
```

**Patterns to avoid (sẽ bị attackers exploit):**
| BAD Message | Attack Vector |
|-------------|---------------|
| "token has expired" | Attacker biết token từng valid |
| "token usage limit reached" | Attacker biết max_uses |
| "agent not found" | Attacker enumerate agent IDs |
| "user not found" vs "invalid password" | User enumeration |

**Generic messages cho authentication:**

```go
// All auth failures should return same message
apierror.Unauthorized("Invalid credentials").WriteJSON(w)
```

### 3. Constant-Time Comparison cho Secrets

**Sử dụng `crypto/subtle` cho so sánh sensitive data:**

```go
import "crypto/subtle"

// BAD - Timing attack vulnerable
if providedHash == storedHash { ... }

// GOOD - Constant-time comparison
if subtle.ConstantTimeCompare([]byte(providedHash), []byte(storedHash)) == 1 { ... }
```

> **Note:** SDK cũng có `credentials.SecureCompare()` function implement constant-time comparison.

### 4. API Keys KHÔNG được trong Query Parameters

```go
// BAD - API key in URL (logged by proxies, browsers)
apiKey := r.URL.Query().Get("api_key")

// GOOD - Only accept from headers
apiKey := r.Header.Get("Authorization") // Bearer token
apiKey := r.Header.Get("X-API-Key")     // Custom header
```

### 5. Sensitive Data trong Request Body (không phải URL)

```go
// BAD - Token in URL
POST /api/v1/register?token=oc-bt-secret123

// GOOD - Token in request body (POST)
POST /api/v1/register
{"bootstrap_token": "oc-bt-secret123"}
```

---

## Common Mistakes to Avoid (Lessons Learned)

### 1. Type Name Conflicts trong Handler Package

**Khi tạo handler mới, kiểm tra type names không conflict với handlers khác:**

```go
// BAD - RegisterRequest đã tồn tại trong local_auth_handler.go
type RegisterRequest struct { ... }

// GOOD - Prefix với domain
type PlatformRegisterRequest struct { ... }
type LocalAuthRegisterRequest struct { ... }
```

### 2. Missing Bounds Validation

**Luôn validate upper/lower bounds cho numeric fields:**

```go
// BAD - No bounds check
req.LeaseDurationSeconds // Could be MaxInt64

// GOOD - Explicit bounds
if req.LeaseDurationSeconds < 10 || req.LeaseDurationSeconds > 300 {
    apierror.BadRequest("lease_duration_seconds must be between 10-300").WriteJSON(w)
}
```

### 3. Handler Defaults vs Service Defaults

**Defaults nên ở service layer, không phải handler:**

```go
// BAD - Handler sets defaults (hard to test, duplicated logic)
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
    if req.MaxJobs <= 0 {
        req.MaxJobs = 5 // Default in handler
    }
}

// GOOD - Service handles defaults
func (s *Service) Process(input Input) {
    if input.MaxJobs <= 0 {
        input.MaxJobs = DefaultMaxJobs // Defined as constant
    }
}
```

### 4. Transaction Boundaries

**Operations trên multiple entities phải trong cùng transaction:**

```go
// BAD - Separate operations, inconsistent state possible
agentRepo.Create(ctx, agent)
leaseRepo.Create(ctx, lease) // If this fails, orphan agent exists

// GOOD - Atomic operation
tx, _ := db.BeginTx(ctx, nil)
defer tx.Rollback()
agentRepo.CreateTx(ctx, tx, agent)
leaseRepo.CreateTx(ctx, tx, lease)
tx.Commit()
```

### 5. Context Extraction Duplication

**Tạo helper function thay vì copy-paste:**

```go
// BAD - Copy-paste in every handler method
agt := middleware.GetPlatformAgentFromContext(r.Context())
if agt == nil {
    apierror.Unauthorized("agent not authenticated").WriteJSON(w)
    return
}

// GOOD - Helper or middleware decorator
func (h *Handler) requireAgent(r *http.Request) (*agent.Agent, error) {
    agt := middleware.GetPlatformAgentFromContext(r.Context())
    if agt == nil {
        return nil, ErrNotAuthenticated
    }
    return agt, nil
}
```

### 6. Scan Method Duplication

**Khi cần scan từ cả Row và Rows, tạo shared helper:**

```go
// BAD - 95% duplicate code
func scanLease(row *sql.Row) (*Lease, error) { /* 80 lines */ }
func scanLeaseFromRows(rows *sql.Rows) (*Lease, error) { /* 79 lines, same logic */ }

// GOOD - Shared scanner interface
type rowScanner interface {
    Scan(dest ...interface{}) error
}

func (r *Repository) scanLease(scanner rowScanner) (*Lease, error) {
    // Single implementation
}
```

### 7. Error Handling - Don't Swallow Errors Silently

```go
// BAD - Error logged but client sees empty result
if err != nil {
    h.logger.Error("failed to get jobs", "error", err)
    // Returns empty jobs - client can't distinguish from "no jobs"
}

// GOOD - Differentiate error states
if err != nil {
    h.logger.Error("failed to get jobs", "error", err)
    // Option 1: Return error to client
    apierror.InternalServerError("job retrieval failed").WriteJSON(w)
    return
    // Option 2: Include error indicator in response
    json.NewEncoder(w).Encode(PollResponse{HasError: true})
}
```

### 8. Consolidate Authentication Errors (Anti-Enumeration)

**Middleware auth failures phải return cùng một error message:**

```go
// BAD - Different errors for different failures (attackers can enumerate)
if !agt.IsPlatformAgent {
    apierror.Forbidden("Not a platform agent").WriteJSON(w)  // ← Reveals agent exists but wrong type
    return
}
if agt.Status != agent.AgentStatusActive {
    apierror.Forbidden("Agent is not active").WriteJSON(w)  // ← Reveals agent status
    return
}

// GOOD - Generic error, log specifics server-side
if !agt.IsPlatformAgent {
    h.logger.Debug("non-platform agent attempted platform auth", "agent_id", agt.ID)
    apierror.Unauthorized("Invalid credentials").WriteJSON(w)
    return
}
if agt.Status != agent.AgentStatusActive {
    h.logger.Debug("inactive agent attempted auth", "agent_id", agt.ID, "status", agt.Status)
    apierror.Unauthorized("Invalid credentials").WriteJSON(w)
    return
}
```

### 9. Multiple Registration Endpoints - Same Security Controls

**Khi có nhiều endpoints cùng chức năng, đảm bảo tất cả đều có cùng security controls:**

```go
// Codebase có 2 registration endpoints:
// 1. /api/v1/platform-agents/register (PlatformAgentHandler.RegisterAgent)
// 2. /api/v1/platform/register (PlatformRegisterHandler.Register)

// Cả hai PHẢI có:
// - Rate limiting (cùng rate limiter instance)
// - Generic error messages
// - Bootstrap token validation

// In routes.go - Share rate limiter across both
platformRegRateLimiter := middleware.NewPlatformRegistrationRateLimiter(cfg, log)

registerPlatformAgentRoutes(router, h, auth, userSync, platformRegRateLimiter.Middleware())
registerPlatformCommunicationRoutes(router, platformH, registerH, platformRegRateLimiter.Middleware())
```

### 10. Switch Case Consolidation for Similar Error Types

**Gộp các error cases có cùng response để tránh code linting issues:**

```go
// BAD - Repetitive cases with same response
case errors.Is(err, agent.ErrBootstrapTokenInvalid):
    apierror.Unauthorized("Invalid token").WriteJSON(w)
case errors.Is(err, agent.ErrBootstrapTokenExpired):
    apierror.Unauthorized("Invalid token").WriteJSON(w)  // Same message!
case errors.Is(err, agent.ErrBootstrapTokenExhausted):
    apierror.Unauthorized("Invalid token").WriteJSON(w)  // Same message!

// GOOD - Consolidate with comma-separated errors
case errors.Is(err, agent.ErrBootstrapTokenInvalid),
    errors.Is(err, agent.ErrBootstrapTokenExpired),
    errors.Is(err, agent.ErrBootstrapTokenExhausted),
    errors.Is(err, agent.ErrBootstrapTokenRevoked):
    h.logger.Warn("bootstrap token validation failed", "error", err)
    apierror.Unauthorized("Invalid or expired bootstrap token").WriteJSON(w)
```

---

## SDK Security Notes

> SDK có security features (v1.1+). Xem `../sdk/docs/SECURITY.md` cho chi tiết.

**Key points khi làm việc với SDK:**

- SDK validates jobs client-side, nhưng **API là authoritative validator**
- SDK dùng `credentials.SecureCompare()` - API cũng nên dùng constant-time comparison
- SDK validates JWT `tenant_id` claim - API là source of truth
- Server phải validate templates trước khi send tới agents (path traversal protection)

---

## Git Commit Guidelines

**Important:** When creating git commits:

1. **Do NOT include Co-Authored-By** or **Generated-By** lines in commit messages
2. Keep commit messages clean and focused on the changes
3. Use conventional commit format when appropriate (feat:, fix:, docs:, etc.)

Example:

```bash
git commit -m "fix(security): add input validation

- Add LIKE pattern escaping
- Fix ORDER BY validation
"
```

---

## Smart Filtering (Asset-Scanner Compatibility)

### Overview

Smart filtering automatically matches assets to compatible scanners based on the tool's `supported_targets` configuration. This prevents wasted compute and silent failures when scanning incompatible assets.

### How It Works

1. **At Scan Creation** (`PreviewScanCompatibility()`):
   - Shows compatibility warning if asset group contains incompatible assets
   - Returns `AssetCompatibilityPreview` with counts and percentages
   - Never blocks scan creation (warn, don't block)

2. **At Scan Trigger** (`filterAssetsForSingleScan()`):
   - Filters assets based on tool's `supported_targets`
   - Returns `FilteringResult` showing scanned vs skipped counts
   - Result included in `run.Context["filtering_result"]`
   - API response includes `filtering_result` field

### Key Components

```
internal/domain/tool/
├── target_mapping.go           # TargetAssetTypeMapping entity
├── repository.go               # TargetMappingRepository interface

internal/app/scan/
├── filtering.go                # AssetFilterService, FilteringResult, AssetCompatibilityPreview
├── crud.go                     # PreviewScanCompatibility() method
├── trigger.go                  # filterAssetsForSingleScan() integration

internal/infra/http/handler/
├── pipeline_handler.go         # FilteringResultResponse, RunResponse.FilteringResult
```

### Database Tables

```sql
-- Target-to-asset-type mappings (managed by admins)
target_asset_type_mappings (
    target_type     TEXT PRIMARY KEY,  -- e.g., "url", "domain", "ip"
    asset_type      TEXT NOT NULL,     -- e.g., "website", "domain", "ip_address"
    is_primary      BOOLEAN DEFAULT false,
    created_at      TIMESTAMP
)

-- Tools have supported_targets array
tools.supported_targets TEXT[]  -- e.g., ["url", "domain", "ip"]
```

### API Response Example

```json
{
  "id": "run-uuid",
  "status": "running",
  "filtering_result": {
    "total_assets": 100,
    "scanned_assets": 75,
    "skipped_assets": 25,
    "unclassified_assets": 10,
    "compatibility_percent": 75.0,
    "was_filtered": true,
    "tool_name": "nuclei",
    "supported_targets": ["url", "domain", "ip"],
    "skip_reasons": [
      {"asset_type": "repository", "count": 15, "reason": "Not compatible"},
      {"asset_type": "unclassified", "count": 10, "reason": "Cannot match"}
    ]
  }
}
```

### Design Principles

1. **Never block** - Always allow scan creation/trigger, just filter incompatible assets
2. **Transparent** - Always show what was scanned vs skipped
3. **Graceful degradation** - If filtering fails, proceed without filtering
4. **Unclassified = skipped** - Assets with type "unclassified" cannot match any target

### Related Files

- RFC: `docs/_internal/rfcs/2026-02-02-asset-types-cleanup.md`
- Migrations: `000151_asset_types_cleanup.sql`, `000152_target_asset_type_mappings.sql`
- Schema: `schemas/ctis/v1/asset.json` (AssetType enum)

---

**Last Updated**: 2026-02-02
