package module

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/logger"
)

// VersionService tracks a per-tenant "module configuration version"
// in Redis. The counter increments on every mutation (toggle, reset,
// preset apply). Consumers use the version for:
//
//   1. ETag headers → 304 Not Modified when the client's cached
//      response matches the current version.
//   2. Redis cache key suffix → old payloads auto-expire rather than
//      needing active DELETEs.
//   3. WebSocket "module.updated" payload → clients compare to their
//      cached version and invalidate their SWR cache accordingly.
//
// The pattern mirrors accesscontrol.PermissionVersionService — same
// INCR-based atomicity, same TTL refresh. One key per tenant rather
// than per (tenant, user) because module state is tenant-scoped.
//
// Key format: mod_ver:{tenant_id} → integer version (starts at 1)
//
// Graceful degradation: on Redis failure, reads return 1 and writes
// are best-effort — the HTTP layer still works, ETag just never
// matches (serving fresh payloads), and WS broadcasts still fire.
type VersionService struct {
	redisClient *redis.Client
	logger      *logger.Logger
}

const (
	moduleVersionPrefix = "mod_ver"
	// 30 days — same as permVersionTTL. Key is renewed on every
	// Increment; if a tenant hasn't toggled in 30 days, the key
	// expires and the next read returns 1. That's fine — the client
	// ETag won't match, which is exactly what we want after dormancy.
	moduleVersionTTL = 30 * 24 * time.Hour
)

// NewVersionService creates a module version tracker.
// A nil redisClient is OK — every method degrades to the default
// (version 1) so the HTTP layer continues to work in tests or when
// Redis is down.
func NewVersionService(redisClient *redis.Client, log *logger.Logger) *VersionService {
	return &VersionService{
		redisClient: redisClient,
		logger:      log.With("service", "module_version"),
	}
}

func (s *VersionService) buildKey(tenantID string) string {
	return fmt.Sprintf("%s:%s", moduleVersionPrefix, tenantID)
}

// Get returns the current module version for the tenant. Returns 1
// when no version exists yet or Redis is unavailable — callers must
// treat this as "unknown / probably changed" rather than a literal
// version.
func (s *VersionService) Get(ctx context.Context, tenantID string) int {
	if s == nil || s.redisClient == nil || tenantID == "" {
		return 1
	}

	val, err := s.redisClient.Client().Get(ctx, s.buildKey(tenantID)).Int()
	if err != nil {
		return 1
	}
	return val
}

// Increment atomically bumps the module version for a tenant and
// refreshes the TTL. Called after every successful toggle / reset /
// preset apply. The returned version is the fresh value, useful for
// embedding in WebSocket broadcasts and log lines.
func (s *VersionService) Increment(ctx context.Context, tenantID string) int {
	if s == nil || s.redisClient == nil || tenantID == "" {
		return 1
	}

	key := s.buildKey(tenantID)
	newVersion, err := s.redisClient.Client().Incr(ctx, key).Result()
	if err != nil {
		s.logger.Warn("failed to increment module version",
			"tenant_id", tenantID, "error", err)
		return 1
	}

	if err := s.redisClient.Client().Expire(ctx, key, moduleVersionTTL).Err(); err != nil {
		// TTL refresh failure is non-fatal — the key still carries the
		// prior TTL from its last write. Worst case: key expires
		// earlier than expected, next read returns 1, clients refetch.
		s.logger.Debug("failed to refresh module version TTL",
			"tenant_id", tenantID, "error", err)
	}

	return int(newVersion)
}
