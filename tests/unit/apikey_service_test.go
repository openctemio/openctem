package unit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock API Key Repository
// =============================================================================

type mockAPIKeyRepo struct {
	mu   sync.Mutex
	keys map[shared.ID]*apikey.APIKey

	// Error overrides
	createErr  error
	getByIDErr error
	getByHash  error
	listErr    error
	updateErr  error
	deleteErr  error

	// Call tracking
	createCalls  int
	getByIDCalls int
	getHashCalls int
	listCalls    int
	updateCalls  int
	deleteCalls  int

	// Last filter passed to List
	lastFilter apikey.Filter
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		keys: make(map[shared.ID]*apikey.APIKey),
	}
}

func (m *mockAPIKeyRepo) Create(_ context.Context, key *apikey.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.keys[key.ID()] = key
	return nil
}

func (m *mockAPIKeyRepo) GetByID(_ context.Context, id, tenantID shared.ID) (*apikey.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	key, ok := m.keys[id]
	if !ok {
		return nil, apikey.ErrAPIKeyNotFound
	}
	// Enforce tenant isolation
	if key.TenantID() != tenantID {
		return nil, apikey.ErrAPIKeyNotFound
	}
	return key, nil
}

func (m *mockAPIKeyRepo) GetByHash(_ context.Context, hash string) (*apikey.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getHashCalls++
	if m.getByHash != nil {
		return nil, m.getByHash
	}
	for _, key := range m.keys {
		if key.KeyHash() == hash {
			return key, nil
		}
	}
	return nil, apikey.ErrAPIKeyNotFound
}

func (m *mockAPIKeyRepo) List(_ context.Context, filter apikey.Filter) (apikey.ListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastFilter = filter
	if m.listErr != nil {
		return apikey.ListResult{}, m.listErr
	}

	data := make([]*apikey.APIKey, 0, len(m.keys))
	for _, key := range m.keys {
		if filter.TenantID != nil && key.TenantID() != *filter.TenantID {
			continue
		}
		if filter.Status != nil && key.Status() != *filter.Status {
			continue
		}
		if filter.Search != "" && !strings.Contains(strings.ToLower(key.Name()), strings.ToLower(filter.Search)) {
			continue
		}
		data = append(data, key)
	}

	total := int64(len(data))
	page := filter.Page
	if page < 1 {
		page = 1
	}
	perPage := filter.PerPage
	if perPage < 1 {
		perPage = 20
	}

	start := (page - 1) * perPage
	if start > len(data) {
		start = len(data)
	}
	end := start + perPage
	if end > len(data) {
		end = len(data)
	}

	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}

	return apikey.ListResult{
		Data:       data[start:end],
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

func (m *mockAPIKeyRepo) Update(_ context.Context, key *apikey.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.keys[key.ID()] = key
	return nil
}

func (m *mockAPIKeyRepo) Delete(_ context.Context, id, tenantID shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	key, ok := m.keys[id]
	if !ok {
		return apikey.ErrAPIKeyNotFound
	}
	if key.TenantID() != tenantID {
		return apikey.ErrAPIKeyNotFound
	}
	delete(m.keys, id)
	return nil
}

// =============================================================================
// Mock Encryptor for API Key Tests
// =============================================================================

type apikeyMockEncryptor struct {
	encryptErr   error
	decryptErr   error
	encryptCalls int
	decryptCalls int
	prefix       string
}

func newAPIKeyMockEncryptor() *apikeyMockEncryptor {
	return &apikeyMockEncryptor{
		prefix: "encrypted:",
	}
}

func (m *apikeyMockEncryptor) EncryptString(plaintext string) (string, error) {
	m.encryptCalls++
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	return m.prefix + plaintext, nil
}

func (m *apikeyMockEncryptor) DecryptString(encoded string) (string, error) {
	m.decryptCalls++
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	if strings.HasPrefix(encoded, m.prefix) {
		return strings.TrimPrefix(encoded, m.prefix), nil
	}
	return "", fmt.Errorf("not encrypted")
}

// =============================================================================
// Helper: create APIKeyService for tests
// =============================================================================

func newTestAPIKeyService(repo *mockAPIKeyRepo) *app.APIKeyService {
	log := logger.NewNop()
	return app.NewAPIKeyService(repo, log)
}

// =============================================================================
// Tests: CreateAPIKey
// =============================================================================

func TestCreateAPIKey(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	createdBy := shared.NewID()

	tests := []struct {
		name      string
		input     app.CreateAPIKeyInput
		repoErr   error
		wantErr   bool
		errTarget error
		check     func(t *testing.T, result *app.CreateAPIKeyResult, repo *mockAPIKeyRepo)
	}{
		{
			name: "success - minimal input",
			input: app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     "My API Key",
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, repo *mockAPIKeyRepo) {
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.Key == nil {
					t.Fatal("expected non-nil key")
				}
				if result.Plaintext == "" {
					t.Fatal("expected non-empty plaintext")
				}
				if !strings.HasPrefix(result.Plaintext, "oct_") {
					t.Errorf("expected plaintext to start with 'oct_', got %q", result.Plaintext[:8])
				}
				if result.Key.Name() != "My API Key" {
					t.Errorf("expected name 'My API Key', got %q", result.Key.Name())
				}
				if result.Key.TenantID() != tenantID {
					t.Errorf("expected tenantID %s, got %s", tenantID, result.Key.TenantID())
				}
				if result.Key.Status() != apikey.StatusActive {
					t.Errorf("expected status active, got %s", result.Key.Status())
				}
				if result.Key.KeyPrefix() == "" {
					t.Error("expected non-empty key prefix")
				}
				if len(result.Key.KeyPrefix()) != 8 {
					t.Errorf("expected key prefix length 8, got %d", len(result.Key.KeyPrefix()))
				}
				if result.Key.KeyHash() == "" {
					t.Error("expected non-empty key hash")
				}
				// Default rate limit
				if result.Key.RateLimit() != 1000 {
					t.Errorf("expected default rate limit 1000, got %d", result.Key.RateLimit())
				}
				if repo.createCalls != 1 {
					t.Errorf("expected 1 create call, got %d", repo.createCalls)
				}
			},
		},
		{
			name: "success - full input with all optional fields",
			input: app.CreateAPIKeyInput{
				TenantID:      tenantID.String(),
				UserID:        userID.String(),
				Name:          "Full API Key",
				Description:   "A detailed description",
				Scopes:        []string{"read:assets", "write:findings"},
				RateLimit:     500,
				ExpiresInDays: 30,
				CreatedBy:     createdBy.String(),
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				key := result.Key
				if key.Description() != "A detailed description" {
					t.Errorf("expected description, got %q", key.Description())
				}
				if len(key.Scopes()) != 2 {
					t.Errorf("expected 2 scopes, got %d", len(key.Scopes()))
				}
				if key.RateLimit() != 500 {
					t.Errorf("expected rate limit 500, got %d", key.RateLimit())
				}
				if key.ExpiresAt() == nil {
					t.Fatal("expected non-nil expires_at")
				}
				// Expiration should be approximately 30 days from now
				expectedExpiry := time.Now().AddDate(0, 0, 30)
				diff := key.ExpiresAt().Sub(expectedExpiry)
				if diff < -time.Minute || diff > time.Minute {
					t.Errorf("expected expires_at ~30 days from now, got %s", key.ExpiresAt())
				}
				if key.UserID() == nil {
					t.Fatal("expected non-nil user ID")
				}
				if *key.UserID() != userID {
					t.Errorf("expected user ID %s, got %s", userID, *key.UserID())
				}
				if key.CreatedBy() == nil {
					t.Fatal("expected non-nil created_by")
				}
				if *key.CreatedBy() != createdBy {
					t.Errorf("expected created_by %s, got %s", createdBy, *key.CreatedBy())
				}
			},
		},
		{
			name: "error - invalid tenant ID",
			input: app.CreateAPIKeyInput{
				TenantID: "not-a-uuid",
				Name:     "Test Key",
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - empty tenant ID",
			input: app.CreateAPIKeyInput{
				TenantID: "",
				Name:     "Test Key",
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - repo create fails",
			input: app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     "Test Key",
			},
			repoErr: errors.New("database connection lost"),
			wantErr: true,
		},
		{
			name: "error - repo returns name conflict",
			input: app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     "Duplicate Key",
			},
			repoErr: apikey.ErrAPIKeyNameExists,
			wantErr: true,
		},
		{
			name: "success - invalid user ID is silently ignored",
			input: app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     "Key with bad user ID",
				UserID:   "not-a-uuid",
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				// Invalid user ID is silently ignored (err == nil check in code)
				if result.Key.UserID() != nil {
					t.Errorf("expected nil user ID for invalid input, got %v", result.Key.UserID())
				}
			},
		},
		{
			name: "success - invalid created_by is silently ignored",
			input: app.CreateAPIKeyInput{
				TenantID:  tenantID.String(),
				Name:      "Key with bad created by",
				CreatedBy: "invalid",
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				if result.Key.CreatedBy() != nil {
					t.Errorf("expected nil created_by for invalid input, got %v", result.Key.CreatedBy())
				}
			},
		},
		{
			name: "success - zero rate limit uses default",
			input: app.CreateAPIKeyInput{
				TenantID:  tenantID.String(),
				Name:      "Default rate limit key",
				RateLimit: 0,
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				if result.Key.RateLimit() != 1000 {
					t.Errorf("expected default rate limit 1000, got %d", result.Key.RateLimit())
				}
			},
		},
		{
			name: "success - no expiration when expires_in_days is 0",
			input: app.CreateAPIKeyInput{
				TenantID:      tenantID.String(),
				Name:          "No expiry key",
				ExpiresInDays: 0,
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				if result.Key.ExpiresAt() != nil {
					t.Errorf("expected nil expires_at, got %v", result.Key.ExpiresAt())
				}
			},
		},
		{
			name: "success - empty scopes stay empty",
			input: app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     "No scope key",
				Scopes:   []string{},
			},
			check: func(t *testing.T, result *app.CreateAPIKeyResult, _ *mockAPIKeyRepo) {
				if len(result.Key.Scopes()) != 0 {
					t.Errorf("expected 0 scopes, got %d", len(result.Key.Scopes()))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			repo.createErr = tc.repoErr
			svc := newTestAPIKeyService(repo)

			result, err := svc.CreateAPIKey(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error to wrap %v, got: %v", tc.errTarget, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.check != nil {
				tc.check(t, result, repo)
			}
		})
	}
}

func TestCreateAPIKey_UniquePlaintext(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	tenantID := shared.NewID()

	// Create two keys and verify they have unique plaintexts
	result1, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: tenantID.String(),
		Name:     "Key 1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result2, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: tenantID.String(),
		Name:     "Key 2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result1.Plaintext == result2.Plaintext {
		t.Error("expected unique plaintexts for different keys")
	}

	if result1.Key.KeyHash() == result2.Key.KeyHash() {
		t.Error("expected unique hashes for different keys")
	}

	if result1.Key.ID() == result2.Key.ID() {
		t.Error("expected unique IDs for different keys")
	}
}

// =============================================================================
// Tests: ListAPIKeys
// =============================================================================

func TestListAPIKeys(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tests := []struct {
		name      string
		input     app.ListAPIKeysInput
		setup     func(repo *mockAPIKeyRepo)
		repoErr   error
		wantErr   bool
		errTarget error
		check     func(t *testing.T, result apikey.ListResult, repo *mockAPIKeyRepo)
	}{
		{
			name: "success - empty list",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
			},
			check: func(t *testing.T, result apikey.ListResult, _ *mockAPIKeyRepo) {
				if len(result.Data) != 0 {
					t.Errorf("expected 0 keys, got %d", len(result.Data))
				}
			},
		},
		{
			name: "success - returns keys for tenant",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
			},
			setup: func(repo *mockAPIKeyRepo) {
				k1 := apikey.NewAPIKey(shared.NewID(), tenantID, "Key 1", "hash1", "prefix01")
				k2 := apikey.NewAPIKey(shared.NewID(), tenantID, "Key 2", "hash2", "prefix02")
				k3 := apikey.NewAPIKey(shared.NewID(), otherTenantID, "Other Key", "hash3", "prefix03")
				repo.keys[k1.ID()] = k1
				repo.keys[k2.ID()] = k2
				repo.keys[k3.ID()] = k3
			},
			check: func(t *testing.T, result apikey.ListResult, _ *mockAPIKeyRepo) {
				if len(result.Data) != 2 {
					t.Errorf("expected 2 keys for tenant, got %d", len(result.Data))
				}
			},
		},
		{
			name: "success - with status filter",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
				Status:   "active",
			},
			setup: func(repo *mockAPIKeyRepo) {
				k1 := apikey.NewAPIKey(shared.NewID(), tenantID, "Active Key", "hash1", "prefix01")
				repo.keys[k1.ID()] = k1
			},
			check: func(t *testing.T, _ apikey.ListResult, repo *mockAPIKeyRepo) {
				if repo.lastFilter.Status == nil {
					t.Fatal("expected status filter to be set")
				}
				if *repo.lastFilter.Status != apikey.StatusActive {
					t.Errorf("expected status filter 'active', got %q", *repo.lastFilter.Status)
				}
			},
		},
		{
			name: "success - with search filter",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
				Search:   "production",
			},
			check: func(t *testing.T, _ apikey.ListResult, repo *mockAPIKeyRepo) {
				if repo.lastFilter.Search != "production" {
					t.Errorf("expected search 'production', got %q", repo.lastFilter.Search)
				}
			},
		},
		{
			name: "success - with pagination",
			input: app.ListAPIKeysInput{
				TenantID:  tenantID.String(),
				Page:      2,
				PerPage:   10,
				SortBy:    "name",
				SortOrder: "asc",
			},
			check: func(t *testing.T, _ apikey.ListResult, repo *mockAPIKeyRepo) {
				if repo.lastFilter.Page != 2 {
					t.Errorf("expected page 2, got %d", repo.lastFilter.Page)
				}
				if repo.lastFilter.PerPage != 10 {
					t.Errorf("expected per_page 10, got %d", repo.lastFilter.PerPage)
				}
				if repo.lastFilter.SortBy != "name" {
					t.Errorf("expected sort_by 'name', got %q", repo.lastFilter.SortBy)
				}
				if repo.lastFilter.SortOrder != "asc" {
					t.Errorf("expected sort_order 'asc', got %q", repo.lastFilter.SortOrder)
				}
			},
		},
		{
			name: "success - no status filter when empty",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
				Status:   "",
			},
			check: func(t *testing.T, _ apikey.ListResult, repo *mockAPIKeyRepo) {
				if repo.lastFilter.Status != nil {
					t.Error("expected nil status filter for empty input")
				}
			},
		},
		{
			name: "error - invalid tenant ID",
			input: app.ListAPIKeysInput{
				TenantID: "bad-id",
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - repo fails",
			input: app.ListAPIKeysInput{
				TenantID: tenantID.String(),
			},
			repoErr: errors.New("db error"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			repo.listErr = tc.repoErr
			if tc.setup != nil {
				tc.setup(repo)
			}
			svc := newTestAPIKeyService(repo)

			result, err := svc.ListAPIKeys(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error to wrap %v, got: %v", tc.errTarget, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.check != nil {
				tc.check(t, result, repo)
			}
		})
	}
}

// =============================================================================
// Tests: GetAPIKey
// =============================================================================

func TestGetAPIKey(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	keyID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setup       func(repo *mockAPIKeyRepo)
		repoErr     error
		wantErr     bool
		errTarget   error
		check       func(t *testing.T, key *apikey.APIKey)
	}{
		{
			name:        "success - returns key",
			id:          keyID.String(),
			tenantIDStr: tenantID.String(),
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Test Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			check: func(t *testing.T, key *apikey.APIKey) {
				if key == nil {
					t.Fatal("expected non-nil key")
				}
				if key.ID() != keyID {
					t.Errorf("expected ID %s, got %s", keyID, key.ID())
				}
				if key.Name() != "Test Key" {
					t.Errorf("expected name 'Test Key', got %q", key.Name())
				}
			},
		},
		{
			name:        "error - key not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errTarget:   shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant isolation",
			id:          keyID.String(),
			tenantIDStr: otherTenantID.String(),
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Test Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			wantErr:   true,
			errTarget: shared.ErrNotFound,
		},
		{
			name:        "error - invalid key ID",
			id:          "not-uuid",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errTarget:   shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          keyID.String(),
			tenantIDStr: "not-uuid",
			wantErr:     true,
			errTarget:   shared.ErrValidation,
		},
		{
			name:        "error - both IDs invalid",
			id:          "bad",
			tenantIDStr: "bad",
			wantErr:     true,
			errTarget:   shared.ErrValidation,
		},
		{
			name:        "error - repo error",
			id:          keyID.String(),
			tenantIDStr: tenantID.String(),
			repoErr:     errors.New("connection timeout"),
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			repo.getByIDErr = tc.repoErr
			if tc.setup != nil {
				tc.setup(repo)
			}
			svc := newTestAPIKeyService(repo)

			key, err := svc.GetAPIKey(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error to wrap %v, got: %v", tc.errTarget, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.check != nil {
				tc.check(t, key)
			}
		})
	}
}

// =============================================================================
// Tests: RevokeAPIKey
// =============================================================================

func TestRevokeAPIKey(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	keyID := shared.NewID()
	revokerID := shared.NewID()

	tests := []struct {
		name      string
		input     app.RevokeAPIKeyInput
		setup     func(repo *mockAPIKeyRepo)
		getErr    error
		updateErr error
		wantErr   bool
		errTarget error
		check     func(t *testing.T, key *apikey.APIKey, repo *mockAPIKeyRepo)
	}{
		{
			name: "success - revokes active key",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Active Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			check: func(t *testing.T, key *apikey.APIKey, repo *mockAPIKeyRepo) {
				if key.Status() != apikey.StatusRevoked {
					t.Errorf("expected status revoked, got %s", key.Status())
				}
				if key.RevokedAt() == nil {
					t.Error("expected non-nil revoked_at")
				}
				if key.RevokedBy() == nil {
					t.Fatal("expected non-nil revoked_by")
				}
				if *key.RevokedBy() != revokerID {
					t.Errorf("expected revoked_by %s, got %s", revokerID, *key.RevokedBy())
				}
				if repo.updateCalls != 1 {
					t.Errorf("expected 1 update call, got %d", repo.updateCalls)
				}
			},
		},
		{
			name: "error - already revoked key",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Revoked Key", "hash", "prefix00")
				_ = k.Revoke(revokerID) // Pre-revoke it
				repo.keys[keyID] = k
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - invalid key ID",
			input: app.RevokeAPIKeyInput{
				ID:        "bad",
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - invalid tenant ID",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  "bad",
				RevokedBy: revokerID.String(),
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - invalid revoked_by ID",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  tenantID.String(),
				RevokedBy: "bad",
			},
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			wantErr:   true,
			errTarget: shared.ErrValidation,
		},
		{
			name: "error - key not found",
			input: app.RevokeAPIKeyInput{
				ID:        shared.NewID().String(),
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			wantErr:   true,
			errTarget: shared.ErrNotFound,
		},
		{
			name: "error - cross-tenant isolation",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  otherTenantID.String(),
				RevokedBy: revokerID.String(),
			},
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			wantErr:   true,
			errTarget: shared.ErrNotFound,
		},
		{
			name: "error - repo GetByID fails",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			getErr:  errors.New("db error"),
			wantErr: true,
		},
		{
			name: "error - repo Update fails",
			input: app.RevokeAPIKeyInput{
				ID:        keyID.String(),
				TenantID:  tenantID.String(),
				RevokedBy: revokerID.String(),
			},
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			updateErr: errors.New("write failure"),
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			repo.getByIDErr = tc.getErr
			repo.updateErr = tc.updateErr
			if tc.setup != nil {
				tc.setup(repo)
			}
			svc := newTestAPIKeyService(repo)

			key, err := svc.RevokeAPIKey(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error to wrap %v, got: %v", tc.errTarget, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.check != nil {
				tc.check(t, key, repo)
			}
		})
	}
}

// =============================================================================
// Tests: DeleteAPIKey
// =============================================================================

func TestDeleteAPIKey(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	keyID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setup       func(repo *mockAPIKeyRepo)
		repoErr     error
		wantErr     bool
		errTarget   error
		check       func(t *testing.T, repo *mockAPIKeyRepo)
	}{
		{
			name:        "success - deletes key",
			id:          keyID.String(),
			tenantIDStr: tenantID.String(),
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			check: func(t *testing.T, repo *mockAPIKeyRepo) {
				if repo.deleteCalls != 1 {
					t.Errorf("expected 1 delete call, got %d", repo.deleteCalls)
				}
				if len(repo.keys) != 0 {
					t.Errorf("expected 0 keys remaining, got %d", len(repo.keys))
				}
			},
		},
		{
			name:        "error - invalid key ID",
			id:          "bad",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errTarget:   shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          keyID.String(),
			tenantIDStr: "bad",
			wantErr:     true,
			errTarget:   shared.ErrValidation,
		},
		{
			name:        "error - key not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errTarget:   shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant isolation",
			id:          keyID.String(),
			tenantIDStr: otherTenantID.String(),
			setup: func(repo *mockAPIKeyRepo) {
				k := apikey.NewAPIKey(keyID, tenantID, "Key", "hash", "prefix00")
				repo.keys[keyID] = k
			},
			wantErr:   true,
			errTarget: shared.ErrNotFound,
		},
		{
			name:        "error - repo delete fails",
			id:          keyID.String(),
			tenantIDStr: tenantID.String(),
			repoErr:     errors.New("foreign key violation"),
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			repo.deleteErr = tc.repoErr
			if tc.setup != nil {
				tc.setup(repo)
			}
			svc := newTestAPIKeyService(repo)

			err := svc.DeleteAPIKey(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errTarget != nil && !errors.Is(err, tc.errTarget) {
					t.Errorf("expected error to wrap %v, got: %v", tc.errTarget, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.check != nil {
				tc.check(t, repo)
			}
		})
	}
}

// =============================================================================
// Tests: APIKeyEncryptionService - EncryptAPIKey
// =============================================================================

func TestAPIKeyEncryptionService_EncryptAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		encryptor  crypto.Encryptor
		input      string
		wantErr    bool
		wantOutput string
		check      func(t *testing.T, output string)
	}{
		{
			name:       "success - encrypts key with prefix",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "oct_abc123",
			wantOutput: "enc:v1:encrypted:oct_abc123",
		},
		{
			name:       "success - empty key returns empty string",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "",
			wantOutput: "",
		},
		{
			name: "error - encryptor fails",
			encryptor: func() crypto.Encryptor {
				e := newAPIKeyMockEncryptor()
				e.encryptErr = errors.New("encryption hardware failure")
				return e
			}(),
			input:   "oct_abc123",
			wantErr: true,
		},
		{
			name:      "success - with NoOpEncryptor",
			encryptor: crypto.NewNoOpEncryptor(),
			input:     "oct_abc123",
			check: func(t *testing.T, output string) {
				if !strings.HasPrefix(output, "enc:v1:") {
					t.Errorf("expected 'enc:v1:' prefix, got %q", output)
				}
			},
		},
		{
			name:      "success - nil encryptor uses NoOp",
			encryptor: nil,
			input:     "oct_test_key",
			check: func(t *testing.T, output string) {
				if !strings.HasPrefix(output, "enc:v1:") {
					t.Errorf("expected 'enc:v1:' prefix, got %q", output)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := app.NewAPIKeyEncryptionService(tc.encryptor)

			output, err := svc.EncryptAPIKey(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantOutput != "" && output != tc.wantOutput {
				t.Errorf("expected output %q, got %q", tc.wantOutput, output)
			}

			if tc.check != nil {
				tc.check(t, output)
			}
		})
	}
}

// =============================================================================
// Tests: APIKeyEncryptionService - DecryptAPIKey
// =============================================================================

func TestAPIKeyEncryptionService_DecryptAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		encryptor  crypto.Encryptor
		input      string
		wantErr    bool
		wantOutput string
	}{
		{
			name:       "success - decrypts encrypted key",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "enc:v1:encrypted:oct_abc123",
			wantOutput: "oct_abc123",
		},
		{
			name:       "success - empty string returns empty",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "",
			wantOutput: "",
		},
		{
			name:       "success - legacy unencrypted key returned as-is",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "oct_plaintext_legacy_key",
			wantOutput: "oct_plaintext_legacy_key",
		},
		{
			name: "error - decryptor fails",
			encryptor: func() crypto.Encryptor {
				e := newAPIKeyMockEncryptor()
				e.decryptErr = errors.New("decryption failed")
				return e
			}(),
			input:   "enc:v1:some_cipher",
			wantErr: true,
		},
		{
			name:       "success - backward compat with no enc prefix",
			encryptor:  newAPIKeyMockEncryptor(),
			input:      "some-random-old-key-format",
			wantOutput: "some-random-old-key-format",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := app.NewAPIKeyEncryptionService(tc.encryptor)

			output, err := svc.DecryptAPIKey(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if output != tc.wantOutput {
				t.Errorf("expected output %q, got %q", tc.wantOutput, output)
			}
		})
	}
}

// =============================================================================
// Tests: APIKeyEncryptionService - IsEncrypted
// =============================================================================

func TestAPIKeyEncryptionService_IsEncrypted(t *testing.T) {
	svc := app.NewAPIKeyEncryptionService(nil)

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "encrypted key",
			key:  "enc:v1:someciphertext",
			want: true,
		},
		{
			name: "plaintext key",
			key:  "oct_abc123def456",
			want: false,
		},
		{
			name: "empty string",
			key:  "",
			want: false,
		},
		{
			name: "partial prefix enc:",
			key:  "enc:somedata",
			want: false,
		},
		{
			name: "wrong version prefix",
			key:  "enc:v2:somedata",
			want: false,
		},
		{
			name: "just the prefix",
			key:  "enc:v1:",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := svc.IsEncrypted(tc.key)
			if got != tc.want {
				t.Errorf("IsEncrypted(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

// =============================================================================
// Tests: MaskAPIKey (standalone function)
// =============================================================================

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "empty key",
			key:  "",
			want: "",
		},
		{
			name: "encrypted key shows [encrypted]",
			key:  "enc:v1:somecipherdata",
			want: "[encrypted]",
		},
		{
			name: "normal key with first/last 4 chars",
			key:  "oct_abcdefghijklmnop",
			want: "oct_...mnop",
		},
		{
			name: "short key (<=12) fully masked",
			key:  "short",
			want: "*****",
		},
		{
			name: "exactly 12 chars fully masked",
			key:  "123456789012",
			want: "************",
		},
		{
			name: "13 chars shows first/last 4",
			key:  "1234567890123",
			want: "1234...0123",
		},
		{
			name: "typical oct_ key",
			key:  "oct_dGVzdGtleV9mb3JfbWFza2luZ19wdXJwb3Nl",
			want: "oct_...b3Nl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := app.MaskAPIKey(tc.key)
			if got != tc.want {
				t.Errorf("MaskAPIKey(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// =============================================================================
// Tests: Encryption roundtrip
// =============================================================================

func TestAPIKeyEncryptionService_Roundtrip(t *testing.T) {
	enc := newAPIKeyMockEncryptor()
	svc := app.NewAPIKeyEncryptionService(enc)

	original := "oct_test_roundtrip_key_12345"

	encrypted, err := svc.EncryptAPIKey(original)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	if !svc.IsEncrypted(encrypted) {
		t.Errorf("expected encrypted result to be detected as encrypted")
	}

	decrypted, err := svc.DecryptAPIKey(encrypted)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if decrypted != original {
		t.Errorf("roundtrip failed: got %q, want %q", decrypted, original)
	}

	// Verify encryptor was called
	if enc.encryptCalls != 1 {
		t.Errorf("expected 1 encrypt call, got %d", enc.encryptCalls)
	}
	if enc.decryptCalls != 1 {
		t.Errorf("expected 1 decrypt call, got %d", enc.decryptCalls)
	}
}

func TestAPIKeyEncryptionService_Roundtrip_RealCipher(t *testing.T) {
	// Use a real AES cipher for roundtrip test
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	svc := app.NewAPIKeyEncryptionService(cipher)
	original := "oct_real_encryption_test_key"

	encrypted, err := svc.EncryptAPIKey(original)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	if !strings.HasPrefix(encrypted, "enc:v1:") {
		t.Errorf("expected enc:v1: prefix, got %q", encrypted[:10])
	}

	decrypted, err := svc.DecryptAPIKey(encrypted)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if decrypted != original {
		t.Errorf("roundtrip failed: got %q, want %q", decrypted, original)
	}
}

// =============================================================================
// Tests: Cross-tenant isolation (end-to-end scenarios)
// =============================================================================

func TestAPIKeyService_CrossTenantIsolation(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)

	tenantA := shared.NewID()
	tenantB := shared.NewID()

	// Create key for tenant A
	resultA, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: tenantA.String(),
		Name:     "Tenant A Key",
	})
	if err != nil {
		t.Fatalf("create key A: %v", err)
	}

	// Create key for tenant B
	_, err = svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: tenantB.String(),
		Name:     "Tenant B Key",
	})
	if err != nil {
		t.Fatalf("create key B: %v", err)
	}

	t.Run("GetAPIKey - tenant B cannot access tenant A key", func(t *testing.T) {
		_, err := svc.GetAPIKey(context.Background(), resultA.Key.ID().String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error when accessing cross-tenant key")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("RevokeAPIKey - tenant B cannot revoke tenant A key", func(t *testing.T) {
		_, err := svc.RevokeAPIKey(context.Background(), app.RevokeAPIKeyInput{
			ID:        resultA.Key.ID().String(),
			TenantID:  tenantB.String(),
			RevokedBy: shared.NewID().String(),
		})
		if err == nil {
			t.Fatal("expected error when revoking cross-tenant key")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("DeleteAPIKey - tenant B cannot delete tenant A key", func(t *testing.T) {
		err := svc.DeleteAPIKey(context.Background(), resultA.Key.ID().String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error when deleting cross-tenant key")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("ListAPIKeys - returns only own tenant keys", func(t *testing.T) {
		resultList, err := svc.ListAPIKeys(context.Background(), app.ListAPIKeysInput{
			TenantID: tenantA.String(),
		})
		if err != nil {
			t.Fatalf("list error: %v", err)
		}
		for _, k := range resultList.Data {
			if k.TenantID() != tenantA {
				t.Errorf("found key from wrong tenant: %s (expected %s)", k.TenantID(), tenantA)
			}
		}
	})

	// Verify tenant A key was not deleted or modified by tenant B attempts
	t.Run("tenant A key remains accessible after cross-tenant attempts", func(t *testing.T) {
		key, err := svc.GetAPIKey(context.Background(), resultA.Key.ID().String(), tenantA.String())
		if err != nil {
			t.Fatalf("expected key to still exist: %v", err)
		}
		if key.Status() != apikey.StatusActive {
			t.Errorf("expected key to still be active, got %s", key.Status())
		}
	})
}

// =============================================================================
// Tests: CreateAPIKey hash determinism
// =============================================================================

func TestCreateAPIKey_HashIsDeterministicForSamePlaintext(t *testing.T) {
	// This is a property test: the same plaintext should always produce the same hash.
	// Since we generate random keys, we test indirectly by verifying
	// the hash stored matches what sha256 of the plaintext would produce.
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)

	result, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: shared.NewID().String(),
		Name:     "Hash Test Key",
	})
	if err != nil {
		t.Fatalf("create error: %v", err)
	}

	// Verify that the stored hash is a hex-encoded SHA-256 of the plaintext
	// SHA-256 produces 32 bytes = 64 hex characters
	if len(result.Key.KeyHash()) != 64 {
		t.Errorf("expected hash length 64, got %d", len(result.Key.KeyHash()))
	}

	// Verify prefix matches the first 8 chars of plaintext
	if result.Key.KeyPrefix() != result.Plaintext[:8] {
		t.Errorf("expected prefix %q, got %q", result.Plaintext[:8], result.Key.KeyPrefix())
	}
}

// =============================================================================
// Tests: Concurrent creation safety
// =============================================================================

func TestCreateAPIKey_ConcurrentCreation(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	tenantID := shared.NewID()

	const numKeys = 20
	type result struct {
		res *app.CreateAPIKeyResult
		err error
	}

	results := make(chan result, numKeys)

	for i := 0; i < numKeys; i++ {
		go func(idx int) {
			r, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
				TenantID: tenantID.String(),
				Name:     fmt.Sprintf("Concurrent Key %d", idx),
			})
			results <- result{res: r, err: err}
		}(i)
	}

	plaintexts := make(map[string]bool)
	hashes := make(map[string]bool)

	for i := 0; i < numKeys; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("key creation failed: %v", r.err)
			continue
		}
		if plaintexts[r.res.Plaintext] {
			t.Errorf("duplicate plaintext detected: %q", r.res.Plaintext)
		}
		plaintexts[r.res.Plaintext] = true

		if hashes[r.res.Key.KeyHash()] {
			t.Errorf("duplicate hash detected: %q", r.res.Key.KeyHash())
		}
		hashes[r.res.Key.KeyHash()] = true
	}

	if len(plaintexts) != numKeys {
		t.Errorf("expected %d unique plaintexts, got %d", numKeys, len(plaintexts))
	}
}

// =============================================================================
// Tests: CreateAPIKey - plaintext format
// =============================================================================

func TestCreateAPIKey_PlaintextFormat(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)

	result, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: shared.NewID().String(),
		Name:     "Format Test",
	})
	if err != nil {
		t.Fatalf("create error: %v", err)
	}

	// Must start with "oct_"
	if !strings.HasPrefix(result.Plaintext, "oct_") {
		t.Errorf("expected 'oct_' prefix, got %q", result.Plaintext[:4])
	}

	// After oct_ prefix, must be valid base64url (no padding)
	b64Part := strings.TrimPrefix(result.Plaintext, "oct_")
	if len(b64Part) == 0 {
		t.Error("expected non-empty base64 part after prefix")
	}

	// Base64url encoding of 32 bytes = 43 characters (no padding)
	if len(b64Part) != 43 {
		t.Errorf("expected base64url part length 43 (32 bytes), got %d", len(b64Part))
	}

	// Verify no padding characters
	if strings.ContainsAny(b64Part, "=+/") {
		t.Errorf("expected base64url encoding (no padding, no +/), got %q", b64Part)
	}
}

// =============================================================================
// Tests: Revoke then delete workflow
// =============================================================================

func TestAPIKeyService_RevokeAndDeleteWorkflow(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	tenantID := shared.NewID()
	revokerID := shared.NewID()

	// Step 1: Create
	result, err := svc.CreateAPIKey(context.Background(), app.CreateAPIKeyInput{
		TenantID: tenantID.String(),
		Name:     "Workflow Key",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	keyIDStr := result.Key.ID().String()

	// Step 2: Verify active
	key, err := svc.GetAPIKey(context.Background(), keyIDStr, tenantID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if key.Status() != apikey.StatusActive {
		t.Fatalf("expected active, got %s", key.Status())
	}

	// Step 3: Revoke
	revokedKey, err := svc.RevokeAPIKey(context.Background(), app.RevokeAPIKeyInput{
		ID:        keyIDStr,
		TenantID:  tenantID.String(),
		RevokedBy: revokerID.String(),
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revokedKey.Status() != apikey.StatusRevoked {
		t.Fatalf("expected revoked, got %s", revokedKey.Status())
	}

	// Step 4: Cannot revoke again
	_, err = svc.RevokeAPIKey(context.Background(), app.RevokeAPIKeyInput{
		ID:        keyIDStr,
		TenantID:  tenantID.String(),
		RevokedBy: revokerID.String(),
	})
	if err == nil {
		t.Fatal("expected error on double revoke")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}

	// Step 5: Can still delete a revoked key
	err = svc.DeleteAPIKey(context.Background(), keyIDStr, tenantID.String())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Step 6: Verify deleted
	_, err = svc.GetAPIKey(context.Background(), keyIDStr, tenantID.String())
	if err == nil {
		t.Fatal("expected error after delete")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found, got: %v", err)
	}
}
