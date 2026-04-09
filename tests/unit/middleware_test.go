package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/user"
)

// Note: KeycloakAuth middleware tests require a mock JWKS server.
// These tests focus on RequireRole and context extraction which don't depend on Keycloak.

func TestRequireRole_Authorized(t *testing.T) {
	handler := middleware.RequireRole("admin", "superuser")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create context with roles (using RolesKey for Keycloak)
	ctx := context.WithValue(context.Background(), middleware.RolesKey, []string{"admin", "user"})
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	handler := middleware.RequireRole("viewer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// User has viewer role among others
	ctx := context.WithValue(context.Background(), middleware.RolesKey, []string{"user", "viewer"})
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	// User has different role
	ctx := context.WithValue(context.Background(), middleware.RolesKey, []string{"user", "viewer"})
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireRole_NoRole(t *testing.T) {
	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	// No roles in context
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestRequireRole_EmptyRoles(t *testing.T) {
	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	// Empty roles slice
	ctx := context.WithValue(context.Background(), middleware.RolesKey, []string{})
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestGetUserID_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-uuid-123")
	userID := middleware.GetUserID(ctx)

	if userID != "user-uuid-123" {
		t.Errorf("expected user-uuid-123, got %s", userID)
	}
}

func TestGetUserID_EmptyContext(t *testing.T) {
	ctx := context.Background()
	userID := middleware.GetUserID(ctx)

	if userID != "" {
		t.Errorf("expected empty string, got %s", userID)
	}
}

func TestGetRole_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.RoleKey, "admin")
	role := middleware.GetRole(ctx)

	if role != "admin" {
		t.Errorf("expected admin, got %s", role)
	}
}

func TestGetRole_EmptyContext(t *testing.T) {
	ctx := context.Background()
	role := middleware.GetRole(ctx)

	if role != "" {
		t.Errorf("expected empty string, got %s", role)
	}
}

func TestGetRoles_FromContext(t *testing.T) {
	expectedRoles := []string{"admin", "user", "viewer"}
	ctx := context.WithValue(context.Background(), middleware.RolesKey, expectedRoles)
	roles := middleware.GetRoles(ctx)

	if len(roles) != len(expectedRoles) {
		t.Errorf("expected %d roles, got %d", len(expectedRoles), len(roles))
	}

	for i, role := range roles {
		if role != expectedRoles[i] {
			t.Errorf("expected role %s at index %d, got %s", expectedRoles[i], i, role)
		}
	}
}

func TestGetRoles_EmptyContext(t *testing.T) {
	ctx := context.Background()
	roles := middleware.GetRoles(ctx)

	if roles != nil {
		t.Errorf("expected nil, got %v", roles)
	}
}

func TestGetEmail_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.EmailKey, "user@example.com")
	email := middleware.GetEmail(ctx)

	if email != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", email)
	}
}

func TestGetEmail_EmptyContext(t *testing.T) {
	ctx := context.Background()
	email := middleware.GetEmail(ctx)

	if email != "" {
		t.Errorf("expected empty string, got %s", email)
	}
}

func TestGetUsername_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.UsernameKey, "johndoe")
	username := middleware.GetUsername(ctx)

	if username != "johndoe" {
		t.Errorf("expected johndoe, got %s", username)
	}
}

func TestGetUsername_EmptyContext(t *testing.T) {
	ctx := context.Background()
	username := middleware.GetUsername(ctx)

	if username != "" {
		t.Errorf("expected empty string, got %s", username)
	}
}

// =============================================================================
// RequireMembership: suspension enforcement
// =============================================================================

// newMembershipTestUser builds a minimal local user usable in middleware tests.
func newMembershipTestUser(t *testing.T) *user.User {
	t.Helper()
	hash := "x"
	return user.Reconstitute(
		shared.NewID(), nil,
		"member@example.com", "Member", "", "",
		user.StatusActive, user.Preferences{}, nil,
		time.Now().UTC(), time.Now().UTC(),
		user.AuthProviderLocal, &hash, true,
		nil, nil, nil, nil, 0, nil,
	)
}

// requireMembershipRequest assembles the context that RequireMembership expects:
// a local user (via LocalUserKey) and a tenant id (via TeamIDKey).
func requireMembershipRequest(u *user.User, tenantID shared.ID) *http.Request {
	ctx := context.Background()
	ctx = context.WithValue(ctx, middleware.LocalUserKey, u)
	ctx = context.WithValue(ctx, middleware.TeamIDKey, tenantID)
	return httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
}

func TestRequireMembership_ActiveMember_Allowed(t *testing.T) {
	u := newMembershipTestUser(t)
	tenantID := shared.NewID()

	m, err := tenant.NewMembership(u.ID(), tenantID, tenant.RoleMember, nil)
	if err != nil {
		t.Fatalf("create membership: %v", err)
	}

	repo := newMockTenantRepo()
	repo.memberships[m.ID().String()] = m

	called := false
	handler := middleware.RequireMembership(repo)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requireMembershipRequest(u, tenantID))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("expected next handler to be called for active member")
	}
}

func TestRequireMembership_SuspendedMember_Rejected(t *testing.T) {
	u := newMembershipTestUser(t)
	tenantID := shared.NewID()
	suspender := shared.NewID()

	m, err := tenant.NewMembership(u.ID(), tenantID, tenant.RoleMember, nil)
	if err != nil {
		t.Fatalf("create membership: %v", err)
	}
	if err := m.Suspend(suspender); err != nil {
		t.Fatalf("suspend membership: %v", err)
	}

	repo := newMockTenantRepo()
	repo.memberships[m.ID().String()] = m

	handler := middleware.RequireMembership(repo)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("next handler must not be called for suspended member")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requireMembershipRequest(u, tenantID))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireMembership_NoMembership_Rejected(t *testing.T) {
	u := newMembershipTestUser(t)
	tenantID := shared.NewID()

	repo := newMockTenantRepo() // empty

	handler := middleware.RequireMembership(repo)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("next handler must not be called when membership missing")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requireMembershipRequest(u, tenantID))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// TestAllContextValues tests that all context values work together
func TestAllContextValues(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, middleware.UserIDKey, "uuid-123")
	ctx = context.WithValue(ctx, middleware.RoleKey, "admin")
	ctx = context.WithValue(ctx, middleware.RolesKey, []string{"admin", "user"})
	ctx = context.WithValue(ctx, middleware.EmailKey, "admin@example.com")
	ctx = context.WithValue(ctx, middleware.UsernameKey, "admin")

	if middleware.GetUserID(ctx) != "uuid-123" {
		t.Error("UserID mismatch")
	}
	if middleware.GetRole(ctx) != "admin" {
		t.Error("Role mismatch")
	}
	if len(middleware.GetRoles(ctx)) != 2 {
		t.Error("Roles count mismatch")
	}
	if middleware.GetEmail(ctx) != "admin@example.com" {
		t.Error("Email mismatch")
	}
	if middleware.GetUsername(ctx) != "admin" {
		t.Error("Username mismatch")
	}
}
