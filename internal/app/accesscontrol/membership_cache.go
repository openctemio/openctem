package accesscontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// MembershipCacheService is a thin Redis-backed wrapper around the
// tenant.Repository.GetMembership lookup that runs on EVERY tenant-
// scoped HTTP request via the RequireMembership middleware. Each
// authenticated dashboard load typically issues 30-50 API calls in
// quick succession, and the previous implementation hit the database
// once per call. The cache replaces those round trips with a Redis
// GET while still respecting the canonical membership lifecycle:
//
//   - On miss → query tenant.Repository, store the result with a
//     short TTL.
//   - On suspend / reactivate / role change / member removal →
//     TenantService calls Invalidate to drop the cached entry, so
//     the next request fetches fresh state.
//   - On Redis failure → fall through to the repository (the cache
//     is best-effort, never load-bearing for correctness).
//
// The cached value is intentionally minimal (membership ID, role,
// status, joined-at) to keep payload small and to avoid stale
// derived data. Downstream code only reads role + status from
// context, so a slim DTO is sufficient.
type MembershipCacheService struct {
	cache *redis.Cache[CachedMembership]
	repo  tenant.Repository
	log   *logger.Logger
}

// CachedMembership is the slim DTO stored in Redis. It carries
// exactly the fields the middleware needs to enforce access
// control and populate the request context.
type CachedMembership struct {
	ID       string    `json:"id"`
	Role     string    `json:"role"`
	Status   string    `json:"status"`
	JoinedAt time.Time `json:"joined_at"`
}

const (
	membershipCachePrefix = "membership"
	membershipCacheTTL    = 5 * time.Minute
)

// NewMembershipCacheService constructs a membership cache. If the
// redis client is unavailable for any reason the constructor returns
// an error and the caller should fall back to direct repository
// access (the wiring code in services.go does this gracefully).
func NewMembershipCacheService(
	redisClient *redis.Client,
	repo tenant.Repository,
	log *logger.Logger,
) (*MembershipCacheService, error) {
	cache, err := redis.NewCache[CachedMembership](redisClient, membershipCachePrefix, membershipCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create membership cache: %w", err)
	}
	return &MembershipCacheService{
		cache: cache,
		repo:  repo,
		log:   log.With("service", "membership_cache"),
	}, nil
}

// cacheKey returns the Redis key for a (tenant, user) pair. Tenant
// comes first so a tenant-wide flush via DeletePattern("tenant:*")
// is straightforward — same shape as the permission cache.
func (s *MembershipCacheService) cacheKey(tenantID, userID shared.ID) string {
	return fmt.Sprintf("%s:%s", tenantID.String(), userID.String())
}

// GetMembership satisfies the middleware.MembershipReader interface.
// It returns a *tenant.Membership reconstructed from cached state on
// hit, or fetches from the repo + populates the cache on miss.
func (s *MembershipCacheService) GetMembership(
	ctx context.Context, userID shared.ID, tenantID shared.ID,
) (*tenant.Membership, error) {
	key := s.cacheKey(tenantID, userID)

	// Try cache first. Any cache error is logged and treated as a
	// miss — the lookup must still serve the request.
	cached, err := s.cache.Get(ctx, key)
	if err == nil && cached != nil {
		return s.reconstructFromCache(*cached, userID, tenantID), nil
	}

	// Cache miss → fetch from the repository.
	m, err := s.repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	// Best-effort cache write. Failure here doesn't affect the
	// caller; the next request will simply miss again.
	val := CachedMembership{
		ID:       m.ID().String(),
		Role:     m.Role().String(),
		Status:   string(m.Status()),
		JoinedAt: m.JoinedAt(),
	}
	if cacheErr := s.cache.Set(ctx, key, val); cacheErr != nil {
		s.log.Warn("failed to cache membership",
			"tenant_id", tenantID.String(),
			"user_id", userID.String(),
			"error", cacheErr)
	}

	return m, nil
}

// Invalidate drops the cached entry for a (tenant, user) pair.
// Called from TenantService whenever a mutation could change role
// or status: SuspendMember, ReactivateMember, UpdateMembership
// (role change), DeleteMembership, AddMember (initial set).
func (s *MembershipCacheService) Invalidate(
	ctx context.Context, tenantID, userID string,
) {
	if tenantID == "" || userID == "" {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return
	}
	key := s.cacheKey(tid, uid)
	if err := s.cache.Delete(ctx, key); err != nil {
		s.log.Warn("failed to invalidate membership cache",
			"tenant_id", tenantID, "user_id", userID, "error", err)
	}
}

// InvalidateForTenant drops every cached membership in a tenant.
// Used when a role mass-update or tenant-wide rule change might
// have shifted the effective role of every member at once.
func (s *MembershipCacheService) InvalidateForTenant(
	ctx context.Context, tenantID string,
) {
	if tenantID == "" {
		return
	}
	pattern := fmt.Sprintf("%s:*", tenantID)
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.log.Warn("failed to invalidate tenant membership cache",
			"tenant_id", tenantID, "error", err)
	}
}

// reconstructFromCache turns the slim cached value back into a
// *tenant.Membership the middleware can inspect. We have neither
// invitedBy nor suspended_at/suspended_by in the cache (they're not
// needed for the access-control check) so they default to nil.
// Reconstitute*WithStatus is reused so the caller never sees an
// inconsistent entity.
func (s *MembershipCacheService) reconstructFromCache(
	v CachedMembership, userID, tenantID shared.ID,
) *tenant.Membership {
	id, err := shared.IDFromString(v.ID)
	if err != nil {
		// Corrupt cache row — return nil-id membership; the next
		// invalidation will replace it.
		id = shared.ID{}
	}
	role, _ := tenant.ParseRole(v.Role)
	return tenant.ReconstituteMembershipWithStatus(
		id, userID, tenantID, role,
		nil,        // invitedBy — not in cache
		v.JoinedAt, // joinedAt
		tenant.MemberStatus(v.Status),
		nil, // suspendedAt — not in cache, never read by middleware
		nil, // suspendedBy — not in cache, never read by middleware
	)
}

// MembershipCacheServiceErrorIsTransient is exposed for tests that
// want to assert the cache layer never returns a fatal error.
var MembershipCacheServiceErrorIsTransient = func(err error) bool {
	if err == nil {
		return true
	}
	return !errors.Is(err, shared.ErrNotFound)
}
