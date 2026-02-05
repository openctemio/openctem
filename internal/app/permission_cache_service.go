package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/logger"
)

// PermissionCacheService provides cached access to user permissions.
// Permissions are cached in Redis with a short TTL for performance.
// On cache miss, permissions are fetched from the database.
//
// Key format: user_perms:{tenant_id}:{user_id} → JSON array of permission strings
// Cache is invalidated when user's roles change.
type PermissionCacheService struct {
	cache      *redis.Cache[[]string]
	roleRepo   role.Repository
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
	roleRepo role.Repository,
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

// cacheKey generates the cache key for a user's permissions.
func (s *PermissionCacheService) cacheKey(tenantID, userID string) string {
	return fmt.Sprintf("%s:%s", tenantID, userID)
}

// GetPermissions returns the permissions for a user.
// First checks Redis cache, then falls back to database.
func (s *PermissionCacheService) GetPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	if tenantID == "" || userID == "" {
		return []string{}, nil
	}

	key := s.cacheKey(tenantID, userID)

	// Try cache first
	cached, err := s.cache.Get(ctx, key)
	if err == nil && cached != nil {
		s.logger.Debug("permission cache hit",
			"tenant_id", tenantID,
			"user_id", userID,
		)
		return *cached, nil
	}

	// Cache miss - fetch from database
	s.logger.Debug("permission cache miss, fetching from DB",
		"tenant_id", tenantID,
		"user_id", userID,
	)

	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}
	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	permissions, err := s.roleRepo.GetUserPermissions(ctx, tid, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions from db: %w", err)
	}

	// Ensure we have a non-nil slice
	if permissions == nil {
		permissions = []string{}
	}

	// Store in cache (ignore errors)
	if cacheErr := s.cache.Set(ctx, key, permissions); cacheErr != nil {
		s.logger.Warn("failed to cache permissions",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", cacheErr,
		)
	}

	return permissions, nil
}

// GetPermissionsWithFallback returns permissions, falling back to database on any cache error.
// Use this when availability is more important than protecting the database.
func (s *PermissionCacheService) GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error) {
	if tenantID == "" || userID == "" {
		return []string{}, nil
	}

	key := s.cacheKey(tenantID, userID)

	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}
	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	// Use GetOrSetFallback which falls back to loader on any cache error
	permissions, err := s.cache.GetOrSetFallback(ctx, key, func(ctx context.Context) (*[]string, error) {
		perms, err := s.roleRepo.GetUserPermissions(ctx, tid, uid)
		if err != nil {
			return nil, err
		}
		if perms == nil {
			perms = []string{}
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

	key := s.cacheKey(tenantID, userID)
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
