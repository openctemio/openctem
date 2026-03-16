package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock User Repository
// =============================================================================

// mockUserRepo implements user.Repository for testing.
type mockUserRepo struct {
	users           map[shared.ID]*user.User
	usersByEmail    map[string]*user.User
	usersByKcID     map[string]*user.User
	createErr       error
	getByIDErr      error
	updateErr       error
	deleteErr       error
	upsertErr       error
	getByEmailErr   error
	getByKcIDErr    error
	getByIDsErr     error
	upsertCallCount int
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:        make(map[shared.ID]*user.User),
		usersByEmail: make(map[string]*user.User),
		usersByKcID:  make(map[string]*user.User),
	}
}

func (m *mockUserRepo) Create(_ context.Context, u *user.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.users[u.ID()] = u
	m.usersByEmail[u.Email()] = u
	if u.KeycloakID() != nil {
		m.usersByKcID[*u.KeycloakID()] = u
	}
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	u, ok := m.users[id]
	if !ok {
		return nil, user.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) GetByKeycloakID(_ context.Context, keycloakID string) (*user.User, error) {
	if m.getByKcIDErr != nil {
		return nil, m.getByKcIDErr
	}
	u, ok := m.usersByKcID[keycloakID]
	if !ok {
		return nil, user.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
	if m.getByEmailErr != nil {
		return nil, m.getByEmailErr
	}
	u, ok := m.usersByEmail[email]
	if !ok {
		return nil, user.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) Update(_ context.Context, u *user.User) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[u.ID()] = u
	m.usersByEmail[u.Email()] = u
	if u.KeycloakID() != nil {
		m.usersByKcID[*u.KeycloakID()] = u
	}
	return nil
}

func (m *mockUserRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	u, ok := m.users[id]
	if !ok {
		return user.ErrUserNotFound
	}
	delete(m.usersByEmail, u.Email())
	if u.KeycloakID() != nil {
		delete(m.usersByKcID, *u.KeycloakID())
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) ExistsByEmail(_ context.Context, email string) (bool, error) {
	_, ok := m.usersByEmail[email]
	return ok, nil
}

func (m *mockUserRepo) ExistsByKeycloakID(_ context.Context, keycloakID string) (bool, error) {
	_, ok := m.usersByKcID[keycloakID]
	return ok, nil
}

func (m *mockUserRepo) UpsertFromKeycloak(_ context.Context, keycloakID, email, name string) (*user.User, error) {
	m.upsertCallCount++
	if m.upsertErr != nil {
		return nil, m.upsertErr
	}
	// Check if user already exists by keycloak ID
	if u, ok := m.usersByKcID[keycloakID]; ok {
		u.SyncFromKeycloak(email, name)
		return u, nil
	}
	// Create new user
	u, err := user.NewFromKeycloak(keycloakID, email, name)
	if err != nil {
		return nil, err
	}
	m.users[u.ID()] = u
	m.usersByEmail[u.Email()] = u
	m.usersByKcID[keycloakID] = u
	return u, nil
}

func (m *mockUserRepo) GetByIDs(_ context.Context, ids []shared.ID) ([]*user.User, error) {
	if m.getByIDsErr != nil {
		return nil, m.getByIDsErr
	}
	result := make([]*user.User, 0, len(ids))
	for _, id := range ids {
		if u, ok := m.users[id]; ok {
			result = append(result, u)
		}
	}
	return result, nil
}

func (m *mockUserRepo) Count(_ context.Context, _ user.Filter) (int64, error) {
	return int64(len(m.users)), nil
}

func (m *mockUserRepo) GetByEmailForAuth(_ context.Context, email string) (*user.User, error) {
	u, ok := m.usersByEmail[email]
	if !ok {
		return nil, user.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmailVerificationToken(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrUserNotFound
}

func (m *mockUserRepo) GetByPasswordResetToken(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrUserNotFound
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestUserService(repo *mockUserRepo) *app.UserService {
	log := logger.NewNop()
	return app.NewUserService(repo, log)
}

// createUserForTest creates a test user and stores it in the mock repo.
func createUserForTest(t *testing.T, repo *mockUserRepo, email, name string) *user.User {
	t.Helper()
	u, err := user.New(email, name)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	if err := repo.Create(context.Background(), u); err != nil {
		t.Fatalf("failed to store test user: %v", err)
	}
	return u
}

// createKeycloakUserForTest creates a test user from Keycloak claims and stores it.
func createKeycloakUserForTest(t *testing.T, repo *mockUserRepo, keycloakID, email, name string) *user.User {
	t.Helper()
	u, err := user.NewFromKeycloak(keycloakID, email, name)
	if err != nil {
		t.Fatalf("failed to create keycloak test user: %v", err)
	}
	if err := repo.Create(context.Background(), u); err != nil {
		t.Fatalf("failed to store keycloak test user: %v", err)
	}
	return u
}

// createSuspendedUserForTest creates a suspended test user.
func createSuspendedUserForTest(t *testing.T, repo *mockUserRepo, email, name string) *user.User {
	t.Helper()
	u := createUserForTest(t, repo, email, name)
	if err := u.Suspend(); err != nil {
		t.Fatalf("failed to suspend test user: %v", err)
	}
	if err := repo.Update(context.Background(), u); err != nil {
		t.Fatalf("failed to update suspended test user: %v", err)
	}
	return u
}

// =============================================================================
// Tests for SyncFromKeycloak
// =============================================================================

func TestSyncFromKeycloak_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "kc-user-123",
		},
		Email: "user@example.com",
		Name:  "John Doe",
	}

	u, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err != nil {
		t.Fatalf("SyncFromKeycloak failed: %v", err)
	}

	if u == nil {
		t.Fatal("Expected non-nil user")
	}
	if u.Email() != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got '%s'", u.Email())
	}
	if u.Name() != "John Doe" {
		t.Errorf("Expected name 'John Doe', got '%s'", u.Name())
	}
}

func TestSyncFromKeycloak_NilClaims(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.SyncFromKeycloak(context.Background(), nil)
	if err == nil {
		t.Fatal("Expected error for nil claims")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestSyncFromKeycloak_EmptyKeycloakID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "", // empty
		},
		Email: "user@example.com",
	}

	_, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err == nil {
		t.Fatal("Expected error for empty keycloak ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestSyncFromKeycloak_EmailFallback(t *testing.T) {
	tests := []struct {
		name          string
		claims        *keycloak.Claims
		expectedEmail string
	}{
		{
			name: "use email field directly",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-1"},
				Email:            "direct@example.com",
			},
			expectedEmail: "direct@example.com",
		},
		{
			name: "fallback to preferred_username",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-2"},
				Email:            "",
				PreferredUsername: "preferred@example.com",
			},
			expectedEmail: "preferred@example.com",
		},
		{
			name: "fallback to placeholder",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-3"},
				Email:            "",
				PreferredUsername: "",
			},
			expectedEmail: "kc-3@placeholder.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			u, err := svc.SyncFromKeycloak(context.Background(), tt.claims)
			if err != nil {
				t.Fatalf("SyncFromKeycloak failed: %v", err)
			}
			if u.Email() != tt.expectedEmail {
				t.Errorf("Expected email '%s', got '%s'", tt.expectedEmail, u.Email())
			}
		})
	}
}

func TestSyncFromKeycloak_NameBuilding(t *testing.T) {
	tests := []struct {
		name         string
		claims       *keycloak.Claims
		expectedName string
	}{
		{
			name: "use name field directly",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-n1"},
				Email:            "n1@test.com",
				Name:             "Full Name",
			},
			expectedName: "Full Name",
		},
		{
			name: "build from given and family name",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-n2"},
				Email:            "n2@test.com",
				Name:             "",
				GivenName:        "John",
				FamilyName:       "Doe",
			},
			expectedName: "John Doe",
		},
		{
			name: "given name only",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-n3"},
				Email:            "n3@test.com",
				Name:             "",
				GivenName:        "Alice",
				FamilyName:       "",
			},
			expectedName: "Alice",
		},
		{
			name: "family name only",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-n4"},
				Email:            "n4@test.com",
				Name:             "",
				GivenName:        "",
				FamilyName:       "Smith",
			},
			expectedName: "Smith",
		},
		{
			name: "fallback to preferred_username",
			claims: &keycloak.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-n5"},
				Email:            "n5@test.com",
				Name:             "",
				GivenName:        "",
				FamilyName:       "",
				PreferredUsername: "johndoe",
			},
			expectedName: "johndoe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			u, err := svc.SyncFromKeycloak(context.Background(), tt.claims)
			if err != nil {
				t.Fatalf("SyncFromKeycloak failed: %v", err)
			}
			if u.Name() != tt.expectedName {
				t.Errorf("Expected name '%s', got '%s'", tt.expectedName, u.Name())
			}
		})
	}
}

func TestSyncFromKeycloak_SanitizesName(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-xss"},
		Email:            "xss@test.com",
		Name:             "<script>alert('xss')</script>",
	}

	u, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err != nil {
		t.Fatalf("SyncFromKeycloak failed: %v", err)
	}
	// Should be HTML-escaped
	if u.Name() == "<script>alert('xss')</script>" {
		t.Error("Expected name to be sanitized (HTML escaped), but it was not")
	}
}

func TestSyncFromKeycloak_RepoError(t *testing.T) {
	repo := newMockUserRepo()
	repo.upsertErr = fmt.Errorf("db connection failed")
	svc := newTestUserService(repo)

	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-err"},
		Email:            "err@test.com",
		Name:             "Error User",
	}

	_, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err == nil {
		t.Fatal("Expected error from repo")
	}
}

func TestSyncFromKeycloak_EmailNormalization(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-norm"},
		Email:            "  USER@EXAMPLE.COM  ",
		Name:             "Normal User",
	}

	u, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err != nil {
		t.Fatalf("SyncFromKeycloak failed: %v", err)
	}
	if u.Email() != "user@example.com" {
		t.Errorf("Expected email to be normalized to 'user@example.com', got '%s'", u.Email())
	}
}

// =============================================================================
// Tests for GetProfile
// =============================================================================

func TestGetProfile_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "profile@test.com", "Profile User")

	result, err := svc.GetProfile(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}
	if result.Email() != "profile@test.com" {
		t.Errorf("Expected email 'profile@test.com', got '%s'", result.Email())
	}
	if result.Name() != "Profile User" {
		t.Errorf("Expected name 'Profile User', got '%s'", result.Name())
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetProfile(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetProfile_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetProfile(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestGetProfile_EmptyID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetProfile(context.Background(), "")
	if err == nil {
		t.Fatal("Expected error for empty ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for GetOrCreateFromLocalToken
// =============================================================================

func TestGetOrCreateFromLocalToken_ExistingUser(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "local@test.com", "Local User")

	result, err := svc.GetOrCreateFromLocalToken(context.Background(), u.ID().String(), "local@test.com", "Local User")
	if err != nil {
		t.Fatalf("GetOrCreateFromLocalToken failed: %v", err)
	}
	if result.ID() != u.ID() {
		t.Errorf("Expected user ID %s, got %s", u.ID(), result.ID())
	}
}

func TestGetOrCreateFromLocalToken_UserNotRegistered(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	nonExistentID := shared.NewID()
	_, err := svc.GetOrCreateFromLocalToken(context.Background(), nonExistentID.String(), "notregistered@test.com", "Not Registered")
	if err == nil {
		t.Fatal("Expected error for unregistered user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetOrCreateFromLocalToken_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetOrCreateFromLocalToken(context.Background(), "invalid-id", "test@test.com", "Test")
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for GetByKeycloakID
// =============================================================================

func TestGetByKeycloakID_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createKeycloakUserForTest(t, repo, "kc-id-123", "kc@test.com", "KC User")

	result, err := svc.GetByKeycloakID(context.Background(), "kc-id-123")
	if err != nil {
		t.Fatalf("GetByKeycloakID failed: %v", err)
	}
	if result.ID() != u.ID() {
		t.Errorf("Expected user ID %s, got %s", u.ID(), result.ID())
	}
}

func TestGetByKeycloakID_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetByKeycloakID(context.Background(), "nonexistent-kc-id")
	if err == nil {
		t.Fatal("Expected error for non-existent Keycloak ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for GetByEmail
// =============================================================================

func TestGetByEmail_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "found@test.com", "Found User")

	result, err := svc.GetByEmail(context.Background(), "found@test.com")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if result.ID() != u.ID() {
		t.Errorf("Expected user ID %s, got %s", u.ID(), result.ID())
	}
}

func TestGetByEmail_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.GetByEmail(context.Background(), "notfound@test.com")
	if err == nil {
		t.Fatal("Expected error for non-existent email")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for UpdateProfile
// =============================================================================

func TestUpdateProfile_Success_AllFields(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "update@test.com", "Original Name")

	newName := "Updated Name"
	newPhone := "+1234567890"
	newAvatar := "https://example.com/avatar.png"

	result, err := svc.UpdateProfile(context.Background(), u.ID().String(), app.UpdateProfileInput{
		Name:      &newName,
		Phone:     &newPhone,
		AvatarURL: &newAvatar,
	})
	if err != nil {
		t.Fatalf("UpdateProfile failed: %v", err)
	}
	if result.Name() != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", result.Name())
	}
	if result.Phone() != "+1234567890" {
		t.Errorf("Expected phone '+1234567890', got '%s'", result.Phone())
	}
	if result.AvatarURL() != "https://example.com/avatar.png" {
		t.Errorf("Expected avatar URL, got '%s'", result.AvatarURL())
	}
}

func TestUpdateProfile_Success_PartialUpdate(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "partial@test.com", "Original Name")

	// Only update name, leave phone and avatar unchanged
	newName := "Partial Update"
	result, err := svc.UpdateProfile(context.Background(), u.ID().String(), app.UpdateProfileInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateProfile failed: %v", err)
	}
	if result.Name() != "Partial Update" {
		t.Errorf("Expected name 'Partial Update', got '%s'", result.Name())
	}
	// Original phone should be preserved (empty for new user)
	if result.Phone() != "" {
		t.Errorf("Expected phone to remain empty, got '%s'", result.Phone())
	}
}

func TestUpdateProfile_Success_NoChanges(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "nochange@test.com", "Same Name")

	// Empty input should keep all fields the same
	result, err := svc.UpdateProfile(context.Background(), u.ID().String(), app.UpdateProfileInput{})
	if err != nil {
		t.Fatalf("UpdateProfile failed: %v", err)
	}
	if result.Name() != "Same Name" {
		t.Errorf("Expected name to remain 'Same Name', got '%s'", result.Name())
	}
}

func TestUpdateProfile_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	newName := "Updated"
	_, err := svc.UpdateProfile(context.Background(), shared.NewID().String(), app.UpdateProfileInput{
		Name: &newName,
	})
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateProfile_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	newName := "Updated"
	_, err := svc.UpdateProfile(context.Background(), "bad-uuid", app.UpdateProfileInput{
		Name: &newName,
	})
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestUpdateProfile_RepoUpdateError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "repoerr@test.com", "Repo Error")
	repo.updateErr = fmt.Errorf("db write failed")

	newName := "Should Fail"
	_, err := svc.UpdateProfile(context.Background(), u.ID().String(), app.UpdateProfileInput{
		Name: &newName,
	})
	if err == nil {
		t.Fatal("Expected error from repo update")
	}
}

// =============================================================================
// Tests for UpdatePreferences
// =============================================================================

func TestUpdatePreferences_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "prefs@test.com", "Prefs User")

	prefs := user.Preferences{
		Theme:         "dark",
		Language:      "en",
		Notifications: true,
	}

	result, err := svc.UpdatePreferences(context.Background(), u.ID().String(), prefs)
	if err != nil {
		t.Fatalf("UpdatePreferences failed: %v", err)
	}
	if result.Preferences().Theme != "dark" {
		t.Errorf("Expected theme 'dark', got '%s'", result.Preferences().Theme)
	}
	if result.Preferences().Language != "en" {
		t.Errorf("Expected language 'en', got '%s'", result.Preferences().Language)
	}
	if !result.Preferences().Notifications {
		t.Error("Expected notifications to be true")
	}
}

func TestUpdatePreferences_OverwriteExisting(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "overwrite@test.com", "Overwrite Prefs")

	// Set initial prefs
	_, err := svc.UpdatePreferences(context.Background(), u.ID().String(), user.Preferences{
		Theme:    "light",
		Language: "vi",
	})
	if err != nil {
		t.Fatalf("First UpdatePreferences failed: %v", err)
	}

	// Overwrite with new prefs
	result, err := svc.UpdatePreferences(context.Background(), u.ID().String(), user.Preferences{
		Theme:    "dark",
		Language: "en",
	})
	if err != nil {
		t.Fatalf("Second UpdatePreferences failed: %v", err)
	}
	if result.Preferences().Theme != "dark" {
		t.Errorf("Expected theme 'dark', got '%s'", result.Preferences().Theme)
	}
	if result.Preferences().Language != "en" {
		t.Errorf("Expected language 'en', got '%s'", result.Preferences().Language)
	}
}

func TestUpdatePreferences_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.UpdatePreferences(context.Background(), shared.NewID().String(), user.Preferences{
		Theme: "dark",
	})
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestUpdatePreferences_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.UpdatePreferences(context.Background(), "invalid-uuid", user.Preferences{})
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestUpdatePreferences_RepoError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "prefserr@test.com", "Prefs Error")
	repo.updateErr = fmt.Errorf("db write failed")

	_, err := svc.UpdatePreferences(context.Background(), u.ID().String(), user.Preferences{Theme: "dark"})
	if err == nil {
		t.Fatal("Expected error from repo")
	}
}

// =============================================================================
// Tests for SuspendUser
// =============================================================================

func TestSuspendUser_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "suspend@test.com", "Suspend Me")

	result, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("SuspendUser failed: %v", err)
	}
	if !result.IsSuspended() {
		t.Error("Expected user to be suspended")
	}
	if result.Status() != user.StatusSuspended {
		t.Errorf("Expected status 'suspended', got '%s'", result.Status())
	}
}

func TestSuspendUser_AlreadySuspended(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createSuspendedUserForTest(t, repo, "already@test.com", "Already Suspended")

	_, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error for already suspended user")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestSuspendUser_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.SuspendUser(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestSuspendUser_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.SuspendUser(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestSuspendUser_RepoUpdateError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "suspenderr@test.com", "Suspend Err")
	repo.updateErr = fmt.Errorf("db write failed")

	_, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error from repo update")
	}
}

func TestSuspendUser_WithSessionService(t *testing.T) {
	// Test that suspension still succeeds even if session revocation fails
	// (the service logs a warning but does not fail the suspend)
	repo := newMockUserRepo()
	svc := newTestUserService(repo)
	// Without SetSessionService, sessionService is nil so no session revocation
	// happens. This tests the nil path.

	u := createUserForTest(t, repo, "sess@test.com", "Session User")

	result, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("SuspendUser failed: %v", err)
	}
	if !result.IsSuspended() {
		t.Error("Expected user to be suspended")
	}
}

// =============================================================================
// Tests for ActivateUser
// =============================================================================

func TestActivateUser_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createSuspendedUserForTest(t, repo, "activate@test.com", "Activate Me")

	result, err := svc.ActivateUser(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("ActivateUser failed: %v", err)
	}
	if !result.IsActive() {
		t.Error("Expected user to be active")
	}
	if result.Status() != user.StatusActive {
		t.Errorf("Expected status 'active', got '%s'", result.Status())
	}
}

func TestActivateUser_AlreadyActive(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "alreadyactive@test.com", "Already Active")

	_, err := svc.ActivateUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error for already active user")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestActivateUser_NotFound(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.ActivateUser(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestActivateUser_InvalidID(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	_, err := svc.ActivateUser(context.Background(), "invalid")
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestActivateUser_RepoUpdateError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createSuspendedUserForTest(t, repo, "activateerr@test.com", "Activate Err")
	repo.updateErr = fmt.Errorf("db write failed")

	_, err := svc.ActivateUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error from repo update")
	}
}

// =============================================================================
// Tests for SuspendUser then ActivateUser (Round-trip)
// =============================================================================

func TestSuspendThenActivate_RoundTrip(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "roundtrip@test.com", "Round Trip")

	// Should start active
	if !u.IsActive() {
		t.Fatal("Expected user to start as active")
	}

	// Suspend
	suspended, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("SuspendUser failed: %v", err)
	}
	if !suspended.IsSuspended() {
		t.Error("Expected user to be suspended")
	}

	// Activate
	activated, err := svc.ActivateUser(context.Background(), u.ID().String())
	if err != nil {
		t.Fatalf("ActivateUser failed: %v", err)
	}
	if !activated.IsActive() {
		t.Error("Expected user to be active again")
	}
}

// =============================================================================
// Tests for GetUsersByIDs (string format)
// =============================================================================

func TestGetUsersByIDs_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u1 := createUserForTest(t, repo, "ids1@test.com", "User 1")
	u2 := createUserForTest(t, repo, "ids2@test.com", "User 2")
	_ = createUserForTest(t, repo, "ids3@test.com", "User 3") // not requested

	result, err := svc.GetUsersByIDs(context.Background(), []string{u1.ID().String(), u2.ID().String()})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result))
	}
}

func TestGetUsersByIDs_EmptyList(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	result, err := svc.GetUsersByIDs(context.Background(), []string{})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 users, got %d", len(result))
	}
}

func TestGetUsersByIDs_SkipsInvalidIDs(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "valid@test.com", "Valid User")

	result, err := svc.GetUsersByIDs(context.Background(), []string{
		u.ID().String(),
		"not-a-uuid",
		"also-invalid",
	})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}
	// Only the valid ID should be queried; invalid IDs are skipped
	if len(result) != 1 {
		t.Errorf("Expected 1 user (valid IDs only), got %d", len(result))
	}
}

func TestGetUsersByIDs_AllInvalidIDs(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	result, err := svc.GetUsersByIDs(context.Background(), []string{"bad-1", "bad-2"})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}
	// All IDs are invalid, so empty valid list is passed to repo
	if len(result) != 0 {
		t.Errorf("Expected 0 users, got %d", len(result))
	}
}

func TestGetUsersByIDs_RepoError(t *testing.T) {
	repo := newMockUserRepo()
	repo.getByIDsErr = fmt.Errorf("db error")
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "repoerr2@test.com", "Repo Err 2")

	_, err := svc.GetUsersByIDs(context.Background(), []string{u.ID().String()})
	if err == nil {
		t.Fatal("Expected error from repo")
	}
}

func TestGetUsersByIDs_NonExistentIDs(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	// Pass valid UUIDs that don't exist in repo
	result, err := svc.GetUsersByIDs(context.Background(), []string{
		shared.NewID().String(),
		shared.NewID().String(),
	})
	if err != nil {
		t.Fatalf("GetUsersByIDs failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 users for non-existent IDs, got %d", len(result))
	}
}

// =============================================================================
// Tests for GetByIDs (shared.ID format)
// =============================================================================

func TestGetByIDs_Success(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u1 := createUserForTest(t, repo, "byids1@test.com", "ByIDs 1")
	u2 := createUserForTest(t, repo, "byids2@test.com", "ByIDs 2")

	result, err := svc.GetByIDs(context.Background(), []shared.ID{u1.ID(), u2.ID()})
	if err != nil {
		t.Fatalf("GetByIDs failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result))
	}
}

func TestGetByIDs_EmptyList(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	result, err := svc.GetByIDs(context.Background(), []shared.ID{})
	if err != nil {
		t.Fatalf("GetByIDs failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 users, got %d", len(result))
	}
}

func TestGetByIDs_NilList(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	result, err := svc.GetByIDs(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetByIDs failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 users, got %d", len(result))
	}
}

func TestGetByIDs_RepoError(t *testing.T) {
	repo := newMockUserRepo()
	repo.getByIDsErr = fmt.Errorf("db error")
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "byidserr@test.com", "ByIDs Err")

	_, err := svc.GetByIDs(context.Background(), []shared.ID{u.ID()})
	if err == nil {
		t.Fatal("Expected error from repo")
	}
}

// =============================================================================
// Tests for SetSessionService
// =============================================================================

func TestSetSessionService_NilAllowed(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	// Should not panic
	svc.SetSessionService(nil)
}

// =============================================================================
// Table-Driven Tests: Comprehensive ID Validation
// =============================================================================

func TestUserService_InvalidIDFormats(t *testing.T) {
	invalidIDs := []struct {
		name string
		id   string
	}{
		{"empty string", ""},
		{"plain text", "not-a-uuid"},
		{"numeric", "12345"},
		{"partial uuid", "550e8400-e29b"},
		{"uuid with extra chars", "550e8400-e29b-41d4-a716-446655440000extra"},
		{"spaces", "  "},
		{"special chars", "!@#$%^&*()"},
	}

	for _, tc := range invalidIDs {
		t.Run("GetProfile_"+tc.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			_, err := svc.GetProfile(context.Background(), tc.id)
			if err == nil {
				t.Errorf("Expected error for ID '%s'", tc.id)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("Expected validation error for ID '%s', got: %v", tc.id, err)
			}
		})

		t.Run("UpdateProfile_"+tc.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			name := "Test"
			_, err := svc.UpdateProfile(context.Background(), tc.id, app.UpdateProfileInput{Name: &name})
			if err == nil {
				t.Errorf("Expected error for ID '%s'", tc.id)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("Expected validation error for ID '%s', got: %v", tc.id, err)
			}
		})

		t.Run("UpdatePreferences_"+tc.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			_, err := svc.UpdatePreferences(context.Background(), tc.id, user.Preferences{})
			if err == nil {
				t.Errorf("Expected error for ID '%s'", tc.id)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("Expected validation error for ID '%s', got: %v", tc.id, err)
			}
		})

		t.Run("SuspendUser_"+tc.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			_, err := svc.SuspendUser(context.Background(), tc.id)
			if err == nil {
				t.Errorf("Expected error for ID '%s'", tc.id)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("Expected validation error for ID '%s', got: %v", tc.id, err)
			}
		})

		t.Run("ActivateUser_"+tc.name, func(t *testing.T) {
			repo := newMockUserRepo()
			svc := newTestUserService(repo)

			_, err := svc.ActivateUser(context.Background(), tc.id)
			if err == nil {
				t.Errorf("Expected error for ID '%s'", tc.id)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("Expected validation error for ID '%s', got: %v", tc.id, err)
			}
		})
	}
}

// =============================================================================
// Tests for SyncFromKeycloak with existing user
// =============================================================================

func TestSyncFromKeycloak_UpdatesExistingUser(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	// First sync creates the user
	claims := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-existing"},
		Email:            "existing@test.com",
		Name:             "Original Name",
	}

	u1, err := svc.SyncFromKeycloak(context.Background(), claims)
	if err != nil {
		t.Fatalf("First SyncFromKeycloak failed: %v", err)
	}

	// Second sync should update the existing user
	claims2 := &keycloak.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "kc-existing"},
		Email:            "newemail@test.com",
		Name:             "Updated Name",
	}

	u2, err := svc.SyncFromKeycloak(context.Background(), claims2)
	if err != nil {
		t.Fatalf("Second SyncFromKeycloak failed: %v", err)
	}

	// Should be the same user (same ID)
	if u1.ID() != u2.ID() {
		t.Errorf("Expected same user ID after upsert, got %s and %s", u1.ID(), u2.ID())
	}

	// Verify upsert was called twice
	if repo.upsertCallCount != 2 {
		t.Errorf("Expected 2 upsert calls, got %d", repo.upsertCallCount)
	}
}

// =============================================================================
// Tests for UpdateProfile with repo GetByID error
// =============================================================================

func TestUpdateProfile_GetByIDError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	// Create a user, then set repo to return error on GetByID
	u := createUserForTest(t, repo, "geterr@test.com", "Get Err User")
	repo.getByIDErr = fmt.Errorf("db connection lost")

	name := "Should Fail"
	_, err := svc.UpdateProfile(context.Background(), u.ID().String(), app.UpdateProfileInput{
		Name: &name,
	})
	if err == nil {
		t.Fatal("Expected error from GetByID")
	}
}

// =============================================================================
// Tests for UpdatePreferences with repo GetByID error
// =============================================================================

func TestUpdatePreferences_GetByIDError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "prefsgeterr@test.com", "Prefs Get Err")
	repo.getByIDErr = fmt.Errorf("db connection lost")

	_, err := svc.UpdatePreferences(context.Background(), u.ID().String(), user.Preferences{Theme: "dark"})
	if err == nil {
		t.Fatal("Expected error from GetByID")
	}
}

// =============================================================================
// Tests for SuspendUser with repo GetByID error
// =============================================================================

func TestSuspendUser_GetByIDError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createUserForTest(t, repo, "suspgeterr@test.com", "Susp Get Err")
	repo.getByIDErr = fmt.Errorf("db connection lost")

	_, err := svc.SuspendUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error from GetByID")
	}
}

// =============================================================================
// Tests for ActivateUser with repo GetByID error
// =============================================================================

func TestActivateUser_GetByIDError(t *testing.T) {
	repo := newMockUserRepo()
	svc := newTestUserService(repo)

	u := createSuspendedUserForTest(t, repo, "actgeterr@test.com", "Act Get Err")
	repo.getByIDErr = fmt.Errorf("db connection lost")

	_, err := svc.ActivateUser(context.Background(), u.ID().String())
	if err == nil {
		t.Fatal("Expected error from GetByID")
	}
}

