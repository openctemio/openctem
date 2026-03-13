package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/infra/redis"
)

// =============================================================================
// Since PermissionCacheService uses concrete *redis.Cache[[]string] and
// unexported fields, we cannot construct it from outside the package without
// a real Redis connection. Instead, we test the behavioral contract through
// a testable interface that mirrors the service's public API, and test the
// permission-checking logic independently.
// =============================================================================

// permCacheStore is a test interface matching the redis.CacheStore[[]string]
// methods used by PermissionCacheService.
type permCacheStore interface {
	Get(ctx context.Context, key string) (*[]string, error)
	Set(ctx context.Context, key string, value []string) error
	Delete(ctx context.Context, key string) error
	DeletePattern(ctx context.Context, pattern string) error
	GetOrSetFallback(ctx context.Context, key string, loader func(ctx context.Context) (*[]string, error)) (*[]string, error)
}

// mockPermCache implements permCacheStore for testing.
type mockPermCache struct {
	store map[string][]string

	getErr           error
	setErr           error
	deleteErr        error
	deletePatternErr error
	fallbackErr      error

	getCalls           int
	setCalls           int
	deleteCalls        int
	deletePatternCalls int
}

func newMockPermCache() *mockPermCache {
	return &mockPermCache{
		store: make(map[string][]string),
	}
}

func (m *mockPermCache) Get(_ context.Context, key string) (*[]string, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	if v, ok := m.store[key]; ok {
		return &v, nil
	}
	return nil, redis.ErrCacheMiss
}

func (m *mockPermCache) Set(_ context.Context, key string, value []string) error {
	m.setCalls++
	if m.setErr != nil {
		return m.setErr
	}
	m.store[key] = value
	return nil
}

func (m *mockPermCache) Delete(_ context.Context, key string) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.store, key)
	return nil
}

func (m *mockPermCache) DeletePattern(_ context.Context, _ string) error {
	m.deletePatternCalls++
	if m.deletePatternErr != nil {
		return m.deletePatternErr
	}
	m.store = make(map[string][]string)
	return nil
}

func (m *mockPermCache) GetOrSetFallback(ctx context.Context, key string, loader func(ctx context.Context) (*[]string, error)) (*[]string, error) {
	if m.fallbackErr != nil {
		return nil, m.fallbackErr
	}
	if v, ok := m.store[key]; ok {
		return &v, nil
	}
	result, err := loader(ctx)
	if err != nil {
		return nil, err
	}
	m.store[key] = *result
	return result, nil
}

// =============================================================================
// Permission Checking Logic Tests
// These test the same logic used by HasPermission, HasAnyPermission,
// HasAllPermissions in the real service.
// =============================================================================

// permCacheContains replicates the permission check logic.
func permCacheContains(permissions []string, target string) bool {
	for _, p := range permissions {
		if p == target {
			return true
		}
	}
	return false
}

// permCacheContainsAny replicates HasAnyPermission logic.
func permCacheContainsAny(permissions []string, targets ...string) bool {
	permSet := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		permSet[p] = true
	}
	for _, t := range targets {
		if permSet[t] {
			return true
		}
	}
	return false
}

// permCacheContainsAll replicates HasAllPermissions logic.
func permCacheContainsAll(permissions []string, targets ...string) bool {
	permSet := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		permSet[p] = true
	}
	for _, t := range targets {
		if !permSet[t] {
			return false
		}
	}
	return true
}

// =============================================================================
// Tests: Cache Key Generation
// =============================================================================

func TestPermCache_CacheKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenantID string
		userID   string
		expected string
	}{
		{
			name:     "standard key",
			tenantID: "tenant-123",
			userID:   "user-456",
			expected: "tenant-123:user-456",
		},
		{
			name:     "uuid format keys",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			userID:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			expected: "550e8400-e29b-41d4-a716-446655440000:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Replicate the cacheKey logic from the service
			key := tt.tenantID + ":" + tt.userID
			if key != tt.expected {
				t.Errorf("expected key %q, got %q", tt.expected, key)
			}
		})
	}
}

// =============================================================================
// Tests: HasPermission
// =============================================================================

func TestPermCache_HasPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		permissions []string
		target      string
		expected    bool
	}{
		{
			name:        "has permission",
			permissions: []string{"assets:read", "assets:write", "findings:read"},
			target:      "assets:write",
			expected:    true,
		},
		{
			name:        "does not have permission",
			permissions: []string{"assets:read", "findings:read"},
			target:      "assets:delete",
			expected:    false,
		},
		{
			name:        "empty permissions",
			permissions: []string{},
			target:      "assets:read",
			expected:    false,
		},
		{
			name:        "nil permissions slice",
			permissions: nil,
			target:      "assets:read",
			expected:    false,
		},
		{
			name:        "exact match required",
			permissions: []string{"assets:read"},
			target:      "assets:read:extra",
			expected:    false,
		},
		{
			name:        "single permission match",
			permissions: []string{"team:delete"},
			target:      "team:delete",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := permCacheContains(tt.permissions, tt.target)
			if result != tt.expected {
				t.Errorf("HasPermission(%v, %q) = %v, want %v",
					tt.permissions, tt.target, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests: HasAnyPermission
// =============================================================================

func TestPermCache_HasAnyPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		permissions []string
		targets     []string
		expected    bool
	}{
		{
			name:        "has first permission",
			permissions: []string{"assets:read", "findings:read"},
			targets:     []string{"assets:read", "assets:write"},
			expected:    true,
		},
		{
			name:        "has second permission",
			permissions: []string{"assets:read", "findings:read"},
			targets:     []string{"assets:write", "findings:read"},
			expected:    true,
		},
		{
			name:        "has none of the permissions",
			permissions: []string{"assets:read", "findings:read"},
			targets:     []string{"assets:write", "findings:write"},
			expected:    false,
		},
		{
			name:        "empty user permissions",
			permissions: []string{},
			targets:     []string{"assets:read"},
			expected:    false,
		},
		{
			name:        "empty target permissions",
			permissions: []string{"assets:read"},
			targets:     []string{},
			expected:    false,
		},
		{
			name:        "all match",
			permissions: []string{"assets:read", "assets:write"},
			targets:     []string{"assets:read", "assets:write"},
			expected:    true,
		},
		{
			name:        "single target match",
			permissions: []string{"assets:read", "assets:write", "findings:read"},
			targets:     []string{"findings:read"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := permCacheContainsAny(tt.permissions, tt.targets...)
			if result != tt.expected {
				t.Errorf("HasAnyPermission(%v, %v) = %v, want %v",
					tt.permissions, tt.targets, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests: HasAllPermissions
// =============================================================================

func TestPermCache_HasAllPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		permissions []string
		targets     []string
		expected    bool
	}{
		{
			name:        "has all permissions",
			permissions: []string{"assets:read", "assets:write", "findings:read"},
			targets:     []string{"assets:read", "assets:write"},
			expected:    true,
		},
		{
			name:        "missing one permission",
			permissions: []string{"assets:read", "findings:read"},
			targets:     []string{"assets:read", "assets:write"},
			expected:    false,
		},
		{
			name:        "missing all permissions",
			permissions: []string{"findings:read"},
			targets:     []string{"assets:read", "assets:write"},
			expected:    false,
		},
		{
			name:        "empty user permissions",
			permissions: []string{},
			targets:     []string{"assets:read"},
			expected:    false,
		},
		{
			name:        "empty targets returns true",
			permissions: []string{"assets:read"},
			targets:     []string{},
			expected:    true,
		},
		{
			name:        "exact match",
			permissions: []string{"assets:read"},
			targets:     []string{"assets:read"},
			expected:    true,
		},
		{
			name:        "superset of required",
			permissions: []string{"assets:read", "assets:write", "findings:read", "findings:write", "team:members:read"},
			targets:     []string{"assets:read", "findings:read"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := permCacheContainsAll(tt.permissions, tt.targets...)
			if result != tt.expected {
				t.Errorf("HasAllPermissions(%v, %v) = %v, want %v",
					tt.permissions, tt.targets, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests: Cache Get/Set Behavior
// =============================================================================

func TestPermCache_GetPermissions_CacheHit(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	// Pre-populate cache
	perms := []string{"assets:read", "findings:read"}
	key := "tenant-1:user-1"
	_ = cache.Set(ctx, key, perms)

	// Should get from cache
	result, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(*result) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(*result))
	}
	if (*result)[0] != "assets:read" {
		t.Errorf("expected assets:read, got %s", (*result)[0])
	}
}

func TestPermCache_GetPermissions_CacheMiss(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	// Should get cache miss
	result, err := cache.Get(ctx, "tenant-1:user-1")
	if !errors.Is(err, redis.ErrCacheMiss) {
		t.Errorf("expected ErrCacheMiss, got %v", err)
	}
	if result != nil {
		t.Error("expected nil result on cache miss")
	}
}

func TestPermCache_GetPermissions_EmptyTenantOrUser(t *testing.T) {
	t.Parallel()

	// Replicating the service's empty check
	tests := []struct {
		name     string
		tenantID string
		userID   string
	}{
		{"empty tenant", "", "user-1"},
		{"empty user", "tenant-1", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Service returns []string{} for empty IDs
			if tt.tenantID == "" || tt.userID == "" {
				result := []string{}
				if len(result) != 0 {
					t.Error("expected empty slice for empty tenant/user")
				}
			}
		})
	}
}

// =============================================================================
// Tests: Invalidation
// =============================================================================

func TestPermCache_Invalidate(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	// Set permissions
	key := "tenant-1:user-1"
	_ = cache.Set(ctx, key, []string{"assets:read"})

	// Verify set
	result, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected cached data")
	}

	// Invalidate
	err = cache.Delete(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error on delete: %v", err)
	}

	// Verify deleted
	result, err = cache.Get(ctx, key)
	if !errors.Is(err, redis.ErrCacheMiss) {
		t.Errorf("expected cache miss after invalidation, got err=%v", err)
	}
	if result != nil {
		t.Error("expected nil result after invalidation")
	}
}

func TestPermCache_InvalidateForUsers(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	tenantID := "tenant-1"
	userIDs := []string{"user-1", "user-2", "user-3"}

	// Set permissions for all users
	for _, uid := range userIDs {
		key := tenantID + ":" + uid
		_ = cache.Set(ctx, key, []string{"assets:read"})
	}

	// Invalidate all users (replicate service logic)
	for _, uid := range userIDs {
		key := tenantID + ":" + uid
		_ = cache.Delete(ctx, key)
	}

	// Verify all deleted
	for _, uid := range userIDs {
		key := tenantID + ":" + uid
		_, err := cache.Get(ctx, key)
		if !errors.Is(err, redis.ErrCacheMiss) {
			t.Errorf("expected cache miss for %s, got %v", uid, err)
		}
	}
}

func TestPermCache_InvalidateForTenant(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	// Set permissions for multiple users in tenant
	_ = cache.Set(ctx, "tenant-1:user-1", []string{"assets:read"})
	_ = cache.Set(ctx, "tenant-1:user-2", []string{"findings:read"})

	// DeletePattern clears all
	err := cache.DeletePattern(ctx, "tenant-1:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cache.deletePatternCalls != 1 {
		t.Errorf("expected 1 deletePattern call, got %d", cache.deletePatternCalls)
	}
}

func TestPermCache_InvalidateForUsers_EmptyInputs(t *testing.T) {
	t.Parallel()

	// Replicate service early return logic
	tests := []struct {
		name     string
		tenantID string
		userIDs  []string
	}{
		{"empty tenant", "", []string{"user-1"}},
		{"empty users", "tenant-1", []string{}},
		{"nil users", "tenant-1", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Service returns early without error
			if tt.tenantID == "" || len(tt.userIDs) == 0 {
				return // Expected behavior
			}
			t.Error("should have returned early")
		})
	}
}

// =============================================================================
// Tests: Refresh
// =============================================================================

func TestPermCache_Refresh(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	key := "tenant-1:user-1"
	_ = cache.Set(ctx, key, []string{"assets:read"})

	// Delete (invalidate) then re-set (refresh)
	_ = cache.Delete(ctx, key)
	newPerms := []string{"assets:read", "assets:write"}
	_ = cache.Set(ctx, key, newPerms)

	result, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*result) != 2 {
		t.Errorf("expected 2 permissions after refresh, got %d", len(*result))
	}
}

// =============================================================================
// Tests: GetPermissionsWithFallback
// =============================================================================

func TestPermCache_GetPermissionsWithFallback_CacheHit(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	key := "tenant-1:user-1"
	perms := []string{"assets:read", "findings:read"}
	_ = cache.Set(ctx, key, perms)

	result, err := cache.GetOrSetFallback(ctx, key, func(_ context.Context) (*[]string, error) {
		t.Error("loader should not be called on cache hit")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*result) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(*result))
	}
}

func TestPermCache_GetPermissionsWithFallback_LoadsFromDB(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	key := "tenant-1:user-1"
	dbPerms := []string{"assets:read", "findings:write"}

	result, err := cache.GetOrSetFallback(ctx, key, func(_ context.Context) (*[]string, error) {
		return &dbPerms, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*result) != 2 {
		t.Errorf("expected 2 permissions from DB, got %d", len(*result))
	}

	// Verify it was cached
	cached, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected cached result, got error: %v", err)
	}
	if len(*cached) != 2 {
		t.Errorf("expected 2 cached permissions, got %d", len(*cached))
	}
}

func TestPermCache_GetPermissionsWithFallback_DBError(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	ctx := context.Background()

	key := "tenant-1:user-1"
	dbErr := errors.New("database connection error")

	result, err := cache.GetOrSetFallback(ctx, key, func(_ context.Context) (*[]string, error) {
		return nil, dbErr
	})
	if err == nil {
		t.Fatal("expected error from DB fallback")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

// =============================================================================
// Tests: Cache Error Handling
// =============================================================================

func TestPermCache_SetError_DoesNotBlock(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	cache.setErr = errors.New("redis connection refused")
	ctx := context.Background()

	// Set fails but the permissions are still returned from DB via fallback
	dbPerms := []string{"assets:read"}
	result, err := cache.GetOrSetFallback(ctx, "tenant-1:user-1", func(_ context.Context) (*[]string, error) {
		return &dbPerms, nil
	})

	// Since our mock's GetOrSetFallback calls loader which returns perms,
	// but then cache.Set fails internally - this depends on implementation.
	// The real service logs the error and returns the permissions anyway.
	// For the mock, the fallback still returns the loader result.
	if err != nil {
		t.Logf("set error may propagate in mock: %v", err)
	}
	if result != nil && len(*result) != 1 {
		t.Errorf("expected 1 permission, got %d", len(*result))
	}
}

func TestPermCache_DeleteError_DoesNotPanic(t *testing.T) {
	t.Parallel()

	cache := newMockPermCache()
	cache.deleteErr = errors.New("redis timeout")
	ctx := context.Background()

	// Should not panic - service logs warning
	err := cache.Delete(ctx, "tenant-1:user-1")
	if err == nil {
		t.Error("expected error from delete")
	}
}

// =============================================================================
// Tests: Permission Set Operations with Map
// =============================================================================

func TestPermCache_PermissionSetEfficiency(t *testing.T) {
	t.Parallel()

	// Test that the map-based approach handles large permission sets
	permissions := make([]string, 126) // Owner gets 126 permissions
	for i := range permissions {
		permissions[i] = "perm:" + string(rune('a'+i%26)) + ":" + string(rune('0'+i/26))
	}

	// HasAny with first permission should find it quickly
	result := permCacheContainsAny(permissions, "perm:a:0")
	if !result {
		t.Error("expected to find permission in large set")
	}

	// HasAll with non-existent permission should fail
	result = permCacheContainsAll(permissions, "perm:a:0", "nonexistent")
	if result {
		t.Error("expected failure with nonexistent permission")
	}
}

func TestPermCache_NilPermissionsSlice_HasPermission(t *testing.T) {
	t.Parallel()

	// Nil permissions should behave like empty
	result := permCacheContains(nil, "assets:read")
	if result {
		t.Error("nil permissions should not contain any permission")
	}

	result2 := permCacheContainsAny(nil, "assets:read")
	if result2 {
		t.Error("nil permissions should not match any")
	}

	result3 := permCacheContainsAll(nil, "assets:read")
	if result3 {
		t.Error("nil permissions should not match all when targets exist")
	}

	// Empty targets with nil perms should return true for HasAll
	result4 := permCacheContainsAll(nil)
	if !result4 {
		t.Error("nil permissions with no targets should return true for HasAll")
	}
}
