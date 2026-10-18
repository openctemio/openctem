package accesscontrol

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/redis"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PermissionCacheService provides cached access to user permissions.
// Permissions are cached in Redis with a short TTL for performance.
// On cache miss, permissions are fetched from the database.
//
// Key format: user_perms:{tenant_id}:{user_id}:v{perm_ver} → JSON array of
// permission strings. The key carries the user's permission version, read
// before the database: a request that loaded the set just before a revocation
// writes it under the old version, which no request reads once the
// revocation has bumped the version. A cache delete alone could not stop that
// write from landing after it. When the version cannot be read the cache is
// bypassed.
type PermissionCacheService struct {
	cache      *redis.Cache[[]string]
	roleRepo   roledom.Repository
	versionSvc *PermissionVersionService
	logger     *logger.Logger
}

const (
	permCachePrefix = "user_perms"
	permCacheTTL    = 5 * time.Minute
)

// NewPermissionCacheService creates a new permission cache service.
func NewPermissionCacheService(
	redisClient *redis.Client,
	roleRepo roledom.Repository,
	versionSvc *PermissionVersionService,
	log *logger.Logger,
) (*PermissionCacheService, error) {
	cache, err := redis.NewCache[[]string](redisClient, permCachePrefix, permCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create permission cache: %w", err)
	}

	return &PermissionCacheService{
		cache:      cache,
		roleRepo:   roleRepo,
		versionSvc: versionSvc,
		logger:     log.With("service", "permission_cache"),
	}, nil
}

// cacheKey generates the cache key for a user's permissions at a version.
func (s *PermissionCacheService) cacheKey(tenantID, userID string, version int) string {
	return fmt.Sprintf("%s:%s:v%d", tenantID, userID, version)
}

// versionedKey reads the user's permission version and returns the key the
// set is cached under. ok is false when the version cannot be read: the
// caller then reads the database and does not touch the cache.
func (s *PermissionCacheService) versionedKey(ctx context.Context, tenantID, userID string) (string, bool) {
	if s.versionSvc == nil {
		return "", false
	}
	v, err := s.versionSvc.Current(ctx, tenantID, userID)
	if err != nil {
		s.logger.Warn("permission version unavailable, bypassing the permission cache",
			"tenant_id", logger.SanitizeValue(tenantID), "user_id", logger.SanitizeValue(userID), "error", err)
		return "", false
	}
	return s.cacheKey(tenantID, userID, v), true
}

// load reads the user's permissions from the database.
func (s *PermissionCacheService) load(ctx context.Context, tenantID, userID string) ([]string, error) {
	tid, err := roledom.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}
	uid, err := roledom.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	permissions, err := s.roleRepo.GetUserPermissions(ctx, tid, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions from db: %w", err)
	}
	if permissions == nil {
		permissions = []string{}
	}
	return permissions, nil
}

// GetPermissions returns the permissions for a user.
// First checks Redis cache, then falls back to database.
func (s *PermissionCacheService) GetPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	if tenantID == "" || userID == "" {
		return []string{}, nil
	}

	// The version is read before the database (see the type comment).
	key, cacheable := s.versionedKey(ctx, tenantID, userID)
	if cacheable {
		cached, err := s.cache.Get(ctx, key)
		if err == nil && cached != nil {
			return *cached, nil
		}
	}

	permissions, err := s.load(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if cacheable {
		if cacheErr := s.cache.Set(ctx, key, permissions); cacheErr != nil {
			s.logger.Warn("failed to cache permissions",
				"tenant_id", tenantID,
				"user_id", userID,
				"error", cacheErr,
			)
		}
	}
	return permissions, nil
}

// GetPermissionsWithFallback returns permissions, falling back to database on any cache error.
// Use this when availability is more important than protecting the database.
func (s *PermissionCacheService) GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error) {
	if tenantID == "" || userID == "" {
		return []string{}, nil
	}

	// The version is read before the database (see the type comment).
	key, cacheable := s.versionedKey(ctx, tenantID, userID)
	if !cacheable {
		return s.load(ctx, tenantID, userID)
	}
	permissions, err := s.cache.GetOrSetFallback(ctx, key, func(ctx context.Context) (*[]string, error) {
		perms, err := s.load(ctx, tenantID, userID)
		if err != nil {
			return nil, err
		}
		return &perms, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	if permissions == nil {
		return []string{}, nil
	}
	return *permissions, nil
}

// Invalidate removes the cached permissions for a user.
// Called when roles are changed.
func (s *PermissionCacheService) Invalidate(ctx context.Context, tenantID, userID string) {
	if tenantID == "" || userID == "" {
		return
	}

	// Drops the entry of the current version. A revocation also bumps the
	// version, which retires every older entry even if this delete fails or
	// a racing loader writes after it.
	key, ok := s.versionedKey(ctx, tenantID, userID)
	if !ok {
		return
	}
	if err := s.cache.Delete(ctx, key); err != nil {
		s.logger.Warn("failed to invalidate permission cache",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", err,
		)
	} else {
		s.logger.Debug("permission cache invalidated",
			"tenant_id", tenantID,
			"user_id", userID,
		)
	}
}

// InvalidateForUsers removes cached permissions for multiple users.
// Called when a role definition is updated.
func (s *PermissionCacheService) InvalidateForUsers(ctx context.Context, tenantID string, userIDs []string) {
	if tenantID == "" || len(userIDs) == 0 {
		return
	}

	for _, userID := range userIDs {
		s.Invalidate(ctx, tenantID, userID)
	}

	s.logger.Info("permission cache invalidated for users",
		"tenant_id", tenantID,
		"user_count", len(userIDs),
	)
}

// InvalidateForTenant removes cached permissions for all users in a tenant.
// Called when a role definition is updated and affects potentially all users.
func (s *PermissionCacheService) InvalidateForTenant(ctx context.Context, tenantID string) {
	if tenantID == "" {
		return
	}

	// Pattern: user_perms:{tenant_id}:*
	pattern := fmt.Sprintf("%s:*", tenantID)
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.logger.Warn("failed to invalidate tenant permission cache",
			"tenant_id", tenantID,
			"error", err,
		)
	} else {
		s.logger.Info("permission cache invalidated for tenant",
			"tenant_id", tenantID,
		)
	}
}

// HasPermission checks if a user has a specific permission.
func (s *PermissionCacheService) HasPermission(ctx context.Context, tenantID, userID, permission string) (bool, error) {
	permissions, err := s.GetPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	return slices.Contains(permissions, permission), nil
}

// HasAnyPermission checks if a user has any of the specified permissions.
func (s *PermissionCacheService) HasAnyPermission(ctx context.Context, tenantID, userID string, permissions ...string) (bool, error) {
	userPerms, err := s.GetPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	permSet := make(map[string]bool, len(userPerms))
	for _, p := range userPerms {
		permSet[p] = true
	}

	for _, p := range permissions {
		if permSet[p] {
			return true, nil
		}
	}
	return false, nil
}

// HasAllPermissions checks if a user has all of the specified permissions.
func (s *PermissionCacheService) HasAllPermissions(ctx context.Context, tenantID, userID string, permissions ...string) (bool, error) {
	userPerms, err := s.GetPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	permSet := make(map[string]bool, len(userPerms))
	for _, p := range userPerms {
		permSet[p] = true
	}

	for _, p := range permissions {
		if !permSet[p] {
			return false, nil
		}
	}
	return true, nil
}

// Refresh refreshes the cached permissions for a user.
// Forces a database fetch and updates the cache.
func (s *PermissionCacheService) Refresh(ctx context.Context, tenantID, userID string) ([]string, error) {
	// Invalidate first
	s.Invalidate(ctx, tenantID, userID)

	// Then fetch fresh
	return s.GetPermissions(ctx, tenantID, userID)
}
