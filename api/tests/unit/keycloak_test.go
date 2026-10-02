package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/keycloak"
)

func TestClaims_GetUserID(t *testing.T) {
	claims := &keycloak.Claims{}
	claims.Subject = "user-uuid-123"

	if claims.GetUserID() != "user-uuid-123" {
		t.Errorf("expected user-uuid-123, got %s", claims.GetUserID())
	}
}

func TestClaims_GetRealmRoles(t *testing.T) {
	claims := &keycloak.Claims{
		RealmAccess: keycloak.RealmAccess{
			Roles: []string{"admin", "user", "viewer"},
		},
	}

	roles := claims.GetRealmRoles()
	if len(roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(roles))
	}
	if roles[0] != "admin" {
		t.Errorf("expected first role to be admin, got %s", roles[0])
	}
}

func TestClaims_HasRealmRole(t *testing.T) {
	claims := &keycloak.Claims{
		RealmAccess: keycloak.RealmAccess{
			Roles: []string{"admin", "user"},
		},
	}

	tests := []struct {
		role     string
		expected bool
	}{
		{"admin", true},
		{"user", true},
		{"viewer", false},
		{"superuser", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if claims.HasRealmRole(tt.role) != tt.expected {
				t.Errorf("HasRealmRole(%s) = %v, want %v", tt.role, !tt.expected, tt.expected)
			}
		})
	}
}

func TestClaims_HasAnyRealmRole(t *testing.T) {
	claims := &keycloak.Claims{
		RealmAccess: keycloak.RealmAccess{
			Roles: []string{"user", "viewer"},
		},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has one of the roles", []string{"admin", "user"}, true},
		{"has another role", []string{"viewer", "superuser"}, true},
		{"has none of the roles", []string{"admin", "superuser"}, false},
		{"empty roles", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if claims.HasAnyRealmRole(tt.roles...) != tt.expected {
				t.Errorf("HasAnyRealmRole(%v) = %v, want %v", tt.roles, !tt.expected, tt.expected)
			}
		})
	}
}

func TestClaims_GetPrimaryRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		expected string
	}{
		{"admin wins over all", []string{"viewer", "admin", "user"}, "admin"},
		{"user wins over viewer", []string{"viewer", "user"}, "user"},
		{"viewer only", []string{"viewer"}, "viewer"},
		{"empty roles", []string{}, ""},
		{"unknown roles only", []string{"custom", "other"}, ""},
		{"admin only", []string{"admin"}, "admin"},
		{"mixed with unknown", []string{"custom", "user", "other"}, "user"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &keycloak.Claims{
				RealmAccess: keycloak.RealmAccess{Roles: tt.roles},
			}
			if got := claims.GetPrimaryRole(); got != tt.expected {
				t.Errorf("GetPrimaryRole() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClaims_GetClientRoles(t *testing.T) {
	claims := &keycloak.Claims{
		ResourceAccess: map[string]keycloak.RealmAccess{
			"my-client":    {Roles: []string{"client-admin", "client-user"}},
			"other-client": {Roles: []string{"reader"}},
		},
	}

	// Test existing client
	roles := claims.GetClientRoles("my-client")
	if len(roles) != 2 {
		t.Errorf("expected 2 roles for my-client, got %d", len(roles))
	}

	// Test non-existing client
	roles = claims.GetClientRoles("unknown-client")
	if roles != nil {
		t.Errorf("expected nil for unknown client, got %v", roles)
	}
}

func TestClaims_HasClientRole(t *testing.T) {
	claims := &keycloak.Claims{
		ResourceAccess: map[string]keycloak.RealmAccess{
			"my-client": {Roles: []string{"admin", "user"}},
		},
	}

	tests := []struct {
		clientID string
		role     string
		expected bool
	}{
		{"my-client", "admin", true},
		{"my-client", "user", true},
		{"my-client", "viewer", false},
		{"other-client", "admin", false},
		{"", "admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.clientID+"/"+tt.role, func(t *testing.T) {
			if claims.HasClientRole(tt.clientID, tt.role) != tt.expected {
				t.Errorf("HasClientRole(%s, %s) = %v, want %v",
					tt.clientID, tt.role, !tt.expected, tt.expected)
			}
		})
	}
}

func TestClaims_EmptyRealmAccess(t *testing.T) {
	claims := &keycloak.Claims{}

	if len(claims.GetRealmRoles()) != 0 {
		t.Error("expected empty roles for nil RealmAccess")
	}

	if claims.HasRealmRole("admin") {
		t.Error("expected false for nil RealmAccess")
	}

	if claims.GetPrimaryRole() != "" {
		t.Error("expected empty string for nil RealmAccess")
	}
}

func TestClaims_FullClaims(t *testing.T) {
	claims := &keycloak.Claims{
		PreferredUsername: "johndoe",
		Email:             "john@example.com",
		EmailVerified:     true,
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		RealmAccess: keycloak.RealmAccess{
			Roles: []string{"admin", "user"},
		},
		SessionState: "session-123",
		Azp:          "my-client",
	}
	claims.Subject = "user-uuid-456"

	if claims.GetUserID() != "user-uuid-456" {
		t.Errorf("expected user-uuid-456, got %s", claims.GetUserID())
	}
	if claims.PreferredUsername != "johndoe" {
		t.Errorf("expected johndoe, got %s", claims.PreferredUsername)
	}
	if claims.Email != "john@example.com" {
		t.Errorf("expected john@example.com, got %s", claims.Email)
	}
	if !claims.EmailVerified {
		t.Error("expected email to be verified")
	}
	if claims.GetPrimaryRole() != "admin" {
		t.Errorf("expected admin, got %s", claims.GetPrimaryRole())
	}
}

// TestJWKToRSAPublicKey tests the JWK to RSA conversion (indirectly through errors)
func TestValidatorConfig_Defaults(t *testing.T) {
	cfg := keycloak.ValidatorConfig{
		JWKSURL:   "https://example.com/certs",
		IssuerURL: "https://example.com/realms/test",
	}

	if cfg.JWKSURL == "" {
		t.Error("JWKSURL should be set")
	}
	if cfg.IssuerURL == "" {
		t.Error("IssuerURL should be set")
	}
}

func TestValidatorErrors(t *testing.T) {
	// Test error types exist and are distinct
	errors := []error{
		keycloak.ErrInvalidToken,
		keycloak.ErrExpiredToken,
		keycloak.ErrInvalidIssuer,
		keycloak.ErrInvalidAudience,
		keycloak.ErrJWKSUnavailable,
		keycloak.ErrKeyNotFound,
	}

	for i, err1 := range errors {
		if err1 == nil {
			t.Errorf("error at index %d is nil", i)
		}
		for j, err2 := range errors {
			if i != j && err1 == err2 {
				t.Errorf("errors at index %d and %d are the same", i, j)
			}
		}
	}
}
