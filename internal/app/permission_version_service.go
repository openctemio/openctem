package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/logger"
)

// PermissionVersionService manages permission version tracking in Redis.
// Version is incremented whenever a user's permissions change (role assigned/removed).
// This enables real-time permission synchronization without embedding permissions in JWT.
//
// Key format: perm_ver:{tenant_id}:{user_id} → integer version
// When admin changes user's roles, the version is incremented.
// JWT contains the version at token generation time.
// If JWT version != Redis version, permissions are stale.
type PermissionVersionService struct {
	redisClient *redis.Client
	logger      *logger.Logger
}

const (
	permVersionPrefix = "perm_ver"
	permVersionTTL    = 30 * 24 * time.Hour // 30 days
)

// NewPermissionVersionService creates a new permission version service.
func NewPermissionVersionService(redisClient *redis.Client, log *logger.Logger) *PermissionVersionService {
	return &PermissionVersionService{
		redisClient: redisClient,
		logger:      log.With("service", "permission_version"),
	}
}

// buildKey generates the Redis key for a user's permission version.
func (s *PermissionVersionService) buildKey(tenantID, userID string) string {
	return fmt.Sprintf("%s:%s:%s", permVersionPrefix, tenantID, userID)
}

// Get returns the current permission version for a user.
// Returns 1 if no version is set (new user).
func (s *PermissionVersionService) Get(ctx context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}

	key := s.buildKey(tenantID, userID)
	val, err := s.redisClient.Client().Get(ctx, key).Int()
	if err != nil {
		// Key doesn't exist or Redis error - return default version 1
		return 1
	}

	return val
}

// Increment atomically increments the permission version for a user.
// Called when roles are assigned, removed, or modified.
// Returns the new version number.
func (s *PermissionVersionService) Increment(ctx context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}

	key := s.buildKey(tenantID, userID)

	// Use INCR for atomic increment
	newVersion, err := s.redisClient.Client().Incr(ctx, key).Result()
	if err != nil {
		s.logger.Error("failed to increment permission version",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", err,
		)
		return 1
	}

	// Set/refresh TTL
	if err := s.redisClient.Client().Expire(ctx, key, permVersionTTL).Err(); err != nil {
		s.logger.Warn("failed to set TTL on permission version",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", err,
		)
	}

	s.logger.Debug("permission version incremented",
		"tenant_id", tenantID,
		"user_id", userID,
		"new_version", newVersion,
	)

	return int(newVersion)
}

// IncrementForUsers increments permission version for multiple users.
// Used when a role definition is updated (affects all users with that role).
func (s *PermissionVersionService) IncrementForUsers(ctx context.Context, tenantID string, userIDs []string) {
	if tenantID == "" || len(userIDs) == 0 {
		return
	}

	for _, userID := range userIDs {
		s.Increment(ctx, tenantID, userID)
	}

	s.logger.Info("permission versions incremented for users",
		"tenant_id", tenantID,
		"user_count", len(userIDs),
	)
}

// Set sets the permission version for a user to a specific value.
// Used during token generation to include current version in JWT.
func (s *PermissionVersionService) Set(ctx context.Context, tenantID, userID string, version int) error {
	if tenantID == "" || userID == "" {
		return fmt.Errorf("tenant_id and user_id are required")
	}

	key := s.buildKey(tenantID, userID)
	if err := s.redisClient.Client().Set(ctx, key, version, permVersionTTL).Err(); err != nil {
		return fmt.Errorf("failed to set permission version: %w", err)
	}

	return nil
}

// EnsureVersion ensures a version exists for the user, initializing to 1 if not.
// Returns the current version (either existing or newly initialized).
func (s *PermissionVersionService) EnsureVersion(ctx context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}

	key := s.buildKey(tenantID, userID)

	// Try to set NX (only if not exists)
	set, err := s.redisClient.Client().SetNX(ctx, key, 1, permVersionTTL).Result()
	if err != nil {
		s.logger.Warn("failed to ensure permission version",
			"tenant_id", tenantID,
			"user_id", userID,
			"error", err,
		)
		return 1
	}

	if set {
		// We just set it to 1
		return 1
	}

	// Already existed, get current value
	return s.Get(ctx, tenantID, userID)
}

// Delete removes the permission version for a user.
// Called when user is removed from tenant.
func (s *PermissionVersionService) Delete(ctx context.Context, tenantID, userID string) error {
	if tenantID == "" || userID == "" {
		return nil
	}

	key := s.buildKey(tenantID, userID)
	if err := s.redisClient.Client().Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete permission version: %w", err)
	}

	s.logger.Debug("permission version deleted",
		"tenant_id", tenantID,
		"user_id", userID,
	)

	return nil
}
