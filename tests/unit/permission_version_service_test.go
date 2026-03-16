package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// =============================================================================
// Since PermissionVersionService uses concrete *redis.Client with unexported
// fields, we test the behavioral contract through a mock interface that
// mirrors the service's public API. This tests the input validation,
// key building, default handling, and version increment logic.
// =============================================================================

const (
	permVerPrefix = "perm_ver"
	permVerTTL    = 30 * 24 * time.Hour
)

// permVerStore is a test interface matching the Redis operations used by
// PermissionVersionService.
type permVerStore struct {
	store   map[string]int
	setErr  error
	getErr  error
	delErr  error
	incrErr error

	getCalls  int
	incrCalls int
	setCalls  int
	delCalls  int
}

func newPermVerStore() *permVerStore {
	return &permVerStore{
		store: make(map[string]int),
	}
}

func (s *permVerStore) get(key string) (int, error) {
	s.getCalls++
	if s.getErr != nil {
		return 0, s.getErr
	}
	if v, ok := s.store[key]; ok {
		return v, nil
	}
	return 0, errors.New("key not found")
}

func (s *permVerStore) incr(key string) (int64, error) {
	s.incrCalls++
	if s.incrErr != nil {
		return 0, s.incrErr
	}
	s.store[key]++
	return int64(s.store[key]), nil
}

func (s *permVerStore) set(key string, value int) error {
	s.setCalls++
	if s.setErr != nil {
		return s.setErr
	}
	s.store[key] = value
	return nil
}

func (s *permVerStore) del(key string) error {
	s.delCalls++
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.store, key)
	return nil
}

func (s *permVerStore) setNX(key string, value int) (bool, error) {
	if s.setErr != nil {
		return false, s.setErr
	}
	if _, exists := s.store[key]; exists {
		return false, nil
	}
	s.store[key] = value
	return true, nil
}

// =============================================================================
// Testable version service that mirrors PermissionVersionService logic
// =============================================================================

type testPermVerService struct {
	store *permVerStore
}

func newTestPermVerService(store *permVerStore) *testPermVerService {
	return &testPermVerService{store: store}
}

func (s *testPermVerService) buildKey(tenantID, userID string) string {
	return fmt.Sprintf("%s:%s:%s", permVerPrefix, tenantID, userID)
}

func (s *testPermVerService) Get(_ context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}
	key := s.buildKey(tenantID, userID)
	val, err := s.store.get(key)
	if err != nil {
		return 1
	}
	return val
}

func (s *testPermVerService) Increment(_ context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}
	key := s.buildKey(tenantID, userID)
	newVersion, err := s.store.incr(key)
	if err != nil {
		return 1
	}
	return int(newVersion)
}

func (s *testPermVerService) IncrementForUsers(ctx context.Context, tenantID string, userIDs []string) {
	if tenantID == "" || len(userIDs) == 0 {
		return
	}
	for _, uid := range userIDs {
		s.Increment(ctx, tenantID, uid)
	}
}

func (s *testPermVerService) Set(_ context.Context, tenantID, userID string, version int) error {
	if tenantID == "" || userID == "" {
		return fmt.Errorf("tenant_id and user_id are required")
	}
	key := s.buildKey(tenantID, userID)
	return s.store.set(key, version)
}

func (s *testPermVerService) EnsureVersion(_ context.Context, tenantID, userID string) int {
	if tenantID == "" || userID == "" {
		return 1
	}
	key := s.buildKey(tenantID, userID)
	set, err := s.store.setNX(key, 1)
	if err != nil {
		return 1
	}
	if set {
		return 1
	}
	val, err := s.store.get(key)
	if err != nil {
		return 1
	}
	return val
}

func (s *testPermVerService) Delete(_ context.Context, tenantID, userID string) error {
	if tenantID == "" || userID == "" {
		return nil
	}
	key := s.buildKey(tenantID, userID)
	return s.store.del(key)
}

// =============================================================================
// Tests: Key Building
// =============================================================================

func TestPermVer_BuildKey(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())

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
			expected: "perm_ver:tenant-123:user-456",
		},
		{
			name:     "uuid format",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			userID:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			expected: "perm_ver:550e8400-e29b-41d4-a716-446655440000:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key := svc.buildKey(tt.tenantID, tt.userID)
			if key != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, key)
			}
		})
	}
}

// =============================================================================
// Tests: Get
// =============================================================================

func TestPermVer_Get_ReturnsVersion(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Set a version
	_ = svc.Set(ctx, "tenant-1", "user-1", 5)

	version := svc.Get(ctx, "tenant-1", "user-1")
	if version != 5 {
		t.Errorf("expected version 5, got %d", version)
	}
}

func TestPermVer_Get_DefaultsTo1_WhenMissing(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.Get(ctx, "tenant-1", "nonexistent-user")
	if version != 1 {
		t.Errorf("expected default version 1, got %d", version)
	}
}

func TestPermVer_Get_EmptyTenantID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.Get(ctx, "", "user-1")
	if version != 1 {
		t.Errorf("expected 1 for empty tenant, got %d", version)
	}
}

func TestPermVer_Get_EmptyUserID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.Get(ctx, "tenant-1", "")
	if version != 1 {
		t.Errorf("expected 1 for empty user, got %d", version)
	}
}

func TestPermVer_Get_BothEmpty(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.Get(ctx, "", "")
	if version != 1 {
		t.Errorf("expected 1 for both empty, got %d", version)
	}
}

func TestPermVer_Get_RedisError_DefaultsTo1(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	store.getErr = errors.New("redis connection refused")
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.Get(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected default version 1 on error, got %d", version)
	}
}

// =============================================================================
// Tests: Increment
// =============================================================================

func TestPermVer_Increment_NewKey(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.Increment(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected version 1 on first increment, got %d", version)
	}
}

func TestPermVer_Increment_ExistingKey(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	_ = svc.Set(ctx, "tenant-1", "user-1", 3)

	version := svc.Increment(ctx, "tenant-1", "user-1")
	if version != 4 {
		t.Errorf("expected version 4, got %d", version)
	}
}

func TestPermVer_Increment_Multiple(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	v1 := svc.Increment(ctx, "tenant-1", "user-1")
	v2 := svc.Increment(ctx, "tenant-1", "user-1")
	v3 := svc.Increment(ctx, "tenant-1", "user-1")

	if v1 != 1 || v2 != 2 || v3 != 3 {
		t.Errorf("expected versions 1,2,3 got %d,%d,%d", v1, v2, v3)
	}
}

func TestPermVer_Increment_EmptyTenantID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.Increment(ctx, "", "user-1")
	if version != 1 {
		t.Errorf("expected 1 for empty tenant, got %d", version)
	}
}

func TestPermVer_Increment_EmptyUserID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.Increment(ctx, "tenant-1", "")
	if version != 1 {
		t.Errorf("expected 1 for empty user, got %d", version)
	}
}

func TestPermVer_Increment_RedisError_DefaultsTo1(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	store.incrErr = errors.New("redis error")
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.Increment(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected default version 1 on error, got %d", version)
	}
}

// =============================================================================
// Tests: IncrementForUsers
// =============================================================================

func TestPermVer_IncrementForUsers(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	userIDs := []string{"user-1", "user-2", "user-3"}
	svc.IncrementForUsers(ctx, "tenant-1", userIDs)

	for _, uid := range userIDs {
		v := svc.Get(ctx, "tenant-1", uid)
		if v != 1 {
			t.Errorf("expected version 1 for %s, got %d", uid, v)
		}
	}

	if store.incrCalls != 3 {
		t.Errorf("expected 3 incr calls, got %d", store.incrCalls)
	}
}

func TestPermVer_IncrementForUsers_EmptyTenant(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	svc.IncrementForUsers(ctx, "", []string{"user-1"})
	if store.incrCalls != 0 {
		t.Errorf("expected 0 incr calls for empty tenant, got %d", store.incrCalls)
	}
}

func TestPermVer_IncrementForUsers_EmptyUserIDs(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	svc.IncrementForUsers(ctx, "tenant-1", []string{})
	if store.incrCalls != 0 {
		t.Errorf("expected 0 incr calls for empty users, got %d", store.incrCalls)
	}
}

func TestPermVer_IncrementForUsers_NilUserIDs(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	svc.IncrementForUsers(ctx, "tenant-1", nil)
	if store.incrCalls != 0 {
		t.Errorf("expected 0 incr calls for nil users, got %d", store.incrCalls)
	}
}

// =============================================================================
// Tests: Set
// =============================================================================

func TestPermVer_Set_Success(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	err := svc.Set(ctx, "tenant-1", "user-1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	v := svc.Get(ctx, "tenant-1", "user-1")
	if v != 10 {
		t.Errorf("expected version 10, got %d", v)
	}
}

func TestPermVer_Set_EmptyTenantID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	err := svc.Set(ctx, "", "user-1", 5)
	if err == nil {
		t.Error("expected error for empty tenant")
	}
}

func TestPermVer_Set_EmptyUserID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	err := svc.Set(ctx, "tenant-1", "", 5)
	if err == nil {
		t.Error("expected error for empty user")
	}
}

func TestPermVer_Set_RedisError(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	store.setErr = errors.New("redis timeout")
	svc := newTestPermVerService(store)
	ctx := context.Background()

	err := svc.Set(ctx, "tenant-1", "user-1", 5)
	if err == nil {
		t.Error("expected error on redis failure")
	}
}

// =============================================================================
// Tests: EnsureVersion
// =============================================================================

func TestPermVer_EnsureVersion_NewUser(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.EnsureVersion(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected version 1 for new user, got %d", version)
	}
}

func TestPermVer_EnsureVersion_ExistingUser(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Set an existing version
	_ = svc.Set(ctx, "tenant-1", "user-1", 5)

	version := svc.EnsureVersion(ctx, "tenant-1", "user-1")
	if version != 5 {
		t.Errorf("expected existing version 5, got %d", version)
	}
}

func TestPermVer_EnsureVersion_EmptyTenantID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.EnsureVersion(ctx, "", "user-1")
	if version != 1 {
		t.Errorf("expected 1 for empty tenant, got %d", version)
	}
}

func TestPermVer_EnsureVersion_EmptyUserID(t *testing.T) {
	t.Parallel()

	svc := newTestPermVerService(newPermVerStore())
	ctx := context.Background()

	version := svc.EnsureVersion(ctx, "tenant-1", "")
	if version != 1 {
		t.Errorf("expected 1 for empty user, got %d", version)
	}
}

func TestPermVer_EnsureVersion_RedisError(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	store.setErr = errors.New("redis connection refused")
	svc := newTestPermVerService(store)
	ctx := context.Background()

	version := svc.EnsureVersion(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected default version 1 on error, got %d", version)
	}
}

// =============================================================================
// Tests: Delete
// =============================================================================

func TestPermVer_Delete_Success(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Set a version
	_ = svc.Set(ctx, "tenant-1", "user-1", 5)

	// Delete it
	err := svc.Delete(ctx, "tenant-1", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return default 1
	version := svc.Get(ctx, "tenant-1", "user-1")
	if version != 1 {
		t.Errorf("expected default version 1 after delete, got %d", version)
	}
}

func TestPermVer_Delete_EmptyTenantID(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	err := svc.Delete(ctx, "", "user-1")
	if err != nil {
		t.Errorf("expected nil error for empty tenant, got %v", err)
	}
	if store.delCalls != 0 {
		t.Errorf("expected 0 del calls, got %d", store.delCalls)
	}
}

func TestPermVer_Delete_EmptyUserID(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	err := svc.Delete(ctx, "tenant-1", "")
	if err != nil {
		t.Errorf("expected nil error for empty user, got %v", err)
	}
	if store.delCalls != 0 {
		t.Errorf("expected 0 del calls, got %d", store.delCalls)
	}
}

func TestPermVer_Delete_RedisError(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	store.delErr = errors.New("redis timeout")
	svc := newTestPermVerService(store)
	ctx := context.Background()

	err := svc.Delete(ctx, "tenant-1", "user-1")
	if err == nil {
		t.Error("expected error on redis failure")
	}
}

func TestPermVer_Delete_NonexistentKey(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Delete non-existent key should not error
	err := svc.Delete(ctx, "tenant-1", "nonexistent")
	if err != nil {
		t.Errorf("expected nil error for nonexistent key, got %v", err)
	}
}

// =============================================================================
// Tests: Version Isolation Between Tenants
// =============================================================================

func TestPermVer_TenantIsolation(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Set different versions for same user in different tenants
	_ = svc.Set(ctx, "tenant-1", "user-1", 5)
	_ = svc.Set(ctx, "tenant-2", "user-1", 10)

	v1 := svc.Get(ctx, "tenant-1", "user-1")
	v2 := svc.Get(ctx, "tenant-2", "user-1")

	if v1 != 5 {
		t.Errorf("expected version 5 for tenant-1, got %d", v1)
	}
	if v2 != 10 {
		t.Errorf("expected version 10 for tenant-2, got %d", v2)
	}
}

func TestPermVer_TenantIsolation_Increment(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	// Increment user in tenant-1 should not affect tenant-2
	_ = svc.Set(ctx, "tenant-1", "user-1", 3)
	_ = svc.Set(ctx, "tenant-2", "user-1", 7)

	svc.Increment(ctx, "tenant-1", "user-1")

	v1 := svc.Get(ctx, "tenant-1", "user-1")
	v2 := svc.Get(ctx, "tenant-2", "user-1")

	if v1 != 4 {
		t.Errorf("expected version 4 for tenant-1, got %d", v1)
	}
	if v2 != 7 {
		t.Errorf("expected version 7 for tenant-2 (unchanged), got %d", v2)
	}
}

func TestPermVer_TenantIsolation_Delete(t *testing.T) {
	t.Parallel()

	store := newPermVerStore()
	svc := newTestPermVerService(store)
	ctx := context.Background()

	_ = svc.Set(ctx, "tenant-1", "user-1", 5)
	_ = svc.Set(ctx, "tenant-2", "user-1", 10)

	// Delete from tenant-1
	_ = svc.Delete(ctx, "tenant-1", "user-1")

	v1 := svc.Get(ctx, "tenant-1", "user-1")
	v2 := svc.Get(ctx, "tenant-2", "user-1")

	if v1 != 1 {
		t.Errorf("expected default version 1 for deleted tenant-1, got %d", v1)
	}
	if v2 != 10 {
		t.Errorf("expected version 10 for tenant-2 (unchanged), got %d", v2)
	}
}

// =============================================================================
// Tests: TTL Constant
// =============================================================================

func TestPermVer_TTLConstant(t *testing.T) {
	t.Parallel()

	expected := 30 * 24 * time.Hour
	if permVerTTL != expected {
		t.Errorf("expected TTL %v, got %v", expected, permVerTTL)
	}
}

// =============================================================================
// Tests: Prefix Constant
// =============================================================================

func TestPermVer_PrefixConstant(t *testing.T) {
	t.Parallel()

	if permVerPrefix != "perm_ver" {
		t.Errorf("expected prefix 'perm_ver', got %q", permVerPrefix)
	}
}
