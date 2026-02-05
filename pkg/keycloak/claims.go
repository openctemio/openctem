// Package keycloak provides Keycloak JWT token validation and claims extraction.
// It integrates with Keycloak's JWKS endpoint for RS256 token validation.
package keycloak

import "github.com/golang-jwt/jwt/v5"

// RealmAccess represents the realm_access claim structure from Keycloak.
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// Claims represents Keycloak JWT token claims.
type Claims struct {
	jwt.RegisteredClaims

	// Keycloak-specific claims
	PreferredUsername string      `json:"preferred_username"`
	Email             string      `json:"email"`
	EmailVerified     bool        `json:"email_verified"`
	Name              string      `json:"name"`
	GivenName         string      `json:"given_name"`
	FamilyName        string      `json:"family_name"`
	RealmAccess       RealmAccess `json:"realm_access"`

	// Resource access (client roles) - optional
	ResourceAccess map[string]RealmAccess `json:"resource_access,omitempty"`

	// Session info
	SessionState string `json:"session_state,omitempty"`
	Azp          string `json:"azp,omitempty"` // Authorized party (client ID)

	// Multi-tenant support
	TenantID    string   `json:"tenant_id,omitempty"`
	TenantRole  string   `json:"tenant_role,omitempty"`  // Primary role within tenant
	TenantRoles []string `json:"tenant_roles,omitempty"` // All roles within tenant
}

// GetUserID returns the subject (user ID) from the token.
func (c *Claims) GetUserID() string {
	return c.Subject
}

// GetRealmRoles returns the realm-level roles.
func (c *Claims) GetRealmRoles() []string {
	return c.RealmAccess.Roles
}

// HasRealmRole checks if the user has a specific realm role.
func (c *Claims) HasRealmRole(role string) bool {
	for _, r := range c.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRealmRole checks if the user has any of the specified realm roles.
func (c *Claims) HasAnyRealmRole(roles ...string) bool {
	for _, required := range roles {
		if c.HasRealmRole(required) {
			return true
		}
	}
	return false
}

// GetPrimaryRole returns the highest-priority role for backward compatibility.
// Priority: admin > user > viewer
func (c *Claims) GetPrimaryRole() string {
	rolePriority := map[string]int{
		"admin":  3,
		"user":   2,
		"viewer": 1,
	}

	var primaryRole string
	var maxPriority int

	for _, role := range c.RealmAccess.Roles {
		if priority, ok := rolePriority[role]; ok && priority > maxPriority {
			maxPriority = priority
			primaryRole = role
		}
	}

	return primaryRole
}

// GetClientRoles returns roles for a specific client.
func (c *Claims) GetClientRoles(clientID string) []string {
	if access, ok := c.ResourceAccess[clientID]; ok {
		return access.Roles
	}
	return nil
}

// HasClientRole checks if the user has a specific role for a client.
func (c *Claims) HasClientRole(clientID, role string) bool {
	roles := c.GetClientRoles(clientID)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetTenantID returns the tenant ID from the token.
func (c *Claims) GetTenantID() string {
	return c.TenantID
}

// GetTenantRole returns the primary role within the tenant.
func (c *Claims) GetTenantRole() string {
	// If TenantRole is set, use it
	if c.TenantRole != "" {
		return c.TenantRole
	}
	// Otherwise, derive from TenantRoles using priority
	return c.GetPrimaryTenantRole()
}

// GetTenantRoles returns all roles within the tenant.
func (c *Claims) GetTenantRoles() []string {
	return c.TenantRoles
}

// GetPrimaryTenantRole returns the highest-priority tenant role.
// Priority: admin > user > viewer
func (c *Claims) GetPrimaryTenantRole() string {
	rolePriority := map[string]int{
		"admin":  3,
		"user":   2,
		"viewer": 1,
	}

	var primaryRole string
	var maxPriority int

	for _, role := range c.TenantRoles {
		if priority, ok := rolePriority[role]; ok && priority > maxPriority {
			maxPriority = priority
			primaryRole = role
		}
	}

	return primaryRole
}

// HasTenantRole checks if the user has a specific role within the tenant.
func (c *Claims) HasTenantRole(role string) bool {
	// Check single role first
	if c.TenantRole == role {
		return true
	}
	// Check roles array
	for _, r := range c.TenantRoles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyTenantRole checks if the user has any of the specified tenant roles.
func (c *Claims) HasAnyTenantRole(roles ...string) bool {
	for _, required := range roles {
		if c.HasTenantRole(required) {
			return true
		}
	}
	return false
}
