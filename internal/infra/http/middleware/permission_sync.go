package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// permSyncTimeout is the maximum time allowed for permission sync operations.
// This prevents DoS if Redis/DB is slow or unresponsive.
const permSyncTimeout = 2 * time.Second

// PermissionSyncMiddleware handles permission synchronization and stale detection.
// It enriches the request context with permissions from Redis cache
// and sets the X-Permission-Stale header when JWT version doesn't match Redis version.
type PermissionSyncMiddleware struct {
	permCache   *app.PermissionCacheService
	permVersion *app.PermissionVersionService
	logger      *logger.Logger
}

// PermSyncContextKey is a context key for permission sync data.
const (
	// FetchedPermissionsKey stores permissions fetched from Redis/DB (not from JWT).
	FetchedPermissionsKey logger.ContextKey = "fetched_permissions"
	// PermVersionKey stores the current permission version from Redis.
	PermVersionKey logger.ContextKey = "perm_version"
	// PermStaleKey indicates if the JWT permission version is stale.
	PermStaleKey logger.ContextKey = "perm_stale"
)

// Response headers for permission sync.
const (
	// HeaderPermissionStale is set to "true" when JWT permission version doesn't match Redis.
	HeaderPermissionStale = "X-Permission-Stale"
	// HeaderPermissionVersion contains the current permission version from Redis.
	HeaderPermissionVersion = "X-Permission-Version"
)

// NewPermissionSyncMiddleware creates a new permission sync middleware.
func NewPermissionSyncMiddleware(
	permCache *app.PermissionCacheService,
	permVersion *app.PermissionVersionService,
	log *logger.Logger,
) *PermissionSyncMiddleware {
	return &PermissionSyncMiddleware{
		permCache:   permCache,
		permVersion: permVersion,
		logger:      log.With("middleware", "permission_sync"),
	}
}

// EnrichPermissions fetches permissions from Redis cache and adds them to context.
// Also checks for stale permissions and sets the X-Permission-Stale header.
//
// This middleware should be placed AFTER UnifiedAuth in the middleware chain.
// It uses the user ID and tenant ID from the context set by UnifiedAuth.
//
// Flow:
// 1. Get tenant ID and user ID from context
// 2. Get current permission version from Redis
// 3. Compare with JWT's perm_version (if present)
// 4. If mismatch: set X-Permission-Stale header
// 5. Fetch permissions from Redis cache (or DB fallback)
// 6. Store permissions in context for handlers
func (m *PermissionSyncMiddleware) EnrichPermissions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get tenant and user from context (set by UnifiedAuth)
		tenantID := MustGetTenantID(ctx)
		userID := GetUserID(ctx)

		// Skip if no tenant or user context
		if tenantID == "" || userID == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Get current permission version from Redis
		currentVersion := m.permVersion.Get(ctx, tenantID, userID)

		// Check JWT's permission version
		var jwtPermVersion int
		if claims := GetLocalClaims(ctx); claims != nil {
			jwtPermVersion = claims.PermVersion
		}

		// Detect stale permissions
		isStale := jwtPermVersion > 0 && jwtPermVersion != currentVersion
		if isStale {
			// Set header to notify frontend that permissions are stale
			w.Header().Set(HeaderPermissionStale, "true")
			w.Header().Set(HeaderPermissionVersion, strconv.Itoa(currentVersion))

			m.logger.Debug("stale permission detected",
				"user_id", userID,
				"tenant_id", tenantID,
				"jwt_version", jwtPermVersion,
				"current_version", currentVersion,
			)
		}

		// Fetch permissions from cache/DB with timeout to prevent DoS
		fetchCtx, cancel := context.WithTimeout(ctx, permSyncTimeout)
		permissions, err := m.permCache.GetPermissionsWithFallback(fetchCtx, tenantID, userID)
		cancel() // Always cancel to release resources
		if err != nil {
			m.logger.Warn("failed to get permissions, using empty list",
				"user_id", userID,
				"tenant_id", tenantID,
				"error", err,
			)
			permissions = []string{}
		}

		// Store in context
		ctx = context.WithValue(ctx, FetchedPermissionsKey, permissions)
		ctx = context.WithValue(ctx, PermVersionKey, currentVersion)
		ctx = context.WithValue(ctx, PermStaleKey, isStale)

		// Also update PermissionsKey so existing HasPermission works
		ctx = context.WithValue(ctx, PermissionsKey, permissions)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetFetchedPermissions returns permissions fetched from Redis/DB.
func GetFetchedPermissions(ctx context.Context) []string {
	if perms, ok := ctx.Value(FetchedPermissionsKey).([]string); ok {
		return perms
	}
	return nil
}

// GetCurrentPermVersion returns the current permission version from Redis.
func GetCurrentPermVersion(ctx context.Context) int {
	if v, ok := ctx.Value(PermVersionKey).(int); ok {
		return v
	}
	return 0
}

// IsPermissionStale returns true if the JWT permission version doesn't match Redis.
func IsPermissionStale(ctx context.Context) bool {
	if stale, ok := ctx.Value(PermStaleKey).(bool); ok {
		return stale
	}
	return false
}

// HasPermissionFromCache checks if user has a permission using fetched permissions.
// Unlike HasPermission which uses JWT permissions + IsAdmin bypass,
// this always uses the latest permissions from cache.
//
// NOTE: For backward compatibility, use HasPermission which still works.
// This function is for explicit cache-based permission checks.
func HasPermissionFromCache(ctx context.Context, permission string) bool {
	perms := GetFetchedPermissions(ctx)
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}
