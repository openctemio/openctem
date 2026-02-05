// Package jwt provides JWT token generation and validation utilities.
package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/tenant"
)

var (
	// ErrInvalidToken is returned when the token is invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken is returned when the token has expired.
	ErrExpiredToken = errors.New("token has expired")
	// ErrEmptyUserID is returned when user_id is empty.
	ErrEmptyUserID = errors.New("user_id cannot be empty")
	// ErrInvalidTokenType is returned when token type is invalid.
	ErrInvalidTokenType = errors.New("invalid token type")
)

// TokenType represents the type of JWT token.
type TokenType string

const (
	// TokenTypeAccess is a short-lived access token.
	TokenTypeAccess TokenType = "access"
	// TokenTypeRefresh is a long-lived refresh token.
	TokenTypeRefresh TokenType = "refresh"
	// TokenTypeJob is a job-specific token for platform agents.
	TokenTypeJob TokenType = "job"
)

// TenantMembership represents a user's membership in a tenant.
type TenantMembership struct {
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug,omitempty"`
	Role       string `json:"role"` // owner, admin, member, viewer
}

// Claims represents the JWT claims structure.
// Supports tenant-based access with granular permissions.
type Claims struct {
	// User identification
	UserID    string    `json:"id"`             // User's unique identifier
	Email     string    `json:"email"`          // User's email address
	Name      string    `json:"name,omitempty"` // User's display name
	SessionID string    `json:"session_id,omitempty"`
	TokenType TokenType `json:"token_type,omitempty"`

	// Multi-tenant access control
	Tenants     []TenantMembership `json:"tenants,omitempty"`     // All tenant memberships
	TenantID    string             `json:"tenant,omitempty"`      // Current tenant context (deprecated, use Tenants)
	Role        string             `json:"role,omitempty"`        // Global role (admin, user)
	Permissions []string           `json:"permissions,omitempty"` // Global permissions (deprecated for slim tokens)
	IsAdmin     bool               `json:"admin,omitempty"`       // Whether user is a system admin (deprecated for slim tokens)

	// Permission version for real-time sync (NEW)
	// When this doesn't match Redis version, permissions are stale
	// Frontend should refresh permissions via GET /api/v1/me/permissions
	PermVersion int `json:"pv,omitempty"`

	jwt.RegisteredClaims
}

// HasPermission checks if the claims include a specific permission.
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the claims include any of the specified permissions.
func (c *Claims) HasAnyPermission(permissions ...string) bool {
	for _, perm := range permissions {
		if c.HasPermission(perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the claims include all specified permissions.
func (c *Claims) HasAllPermissions(permissions ...string) bool {
	for _, perm := range permissions {
		if !c.HasPermission(perm) {
			return false
		}
	}
	return true
}

// HasTenantAccess checks if user has access to a specific tenant.
func (c *Claims) HasTenantAccess(tenantID string) bool {
	for _, t := range c.Tenants {
		if t.TenantID == tenantID {
			return true
		}
	}
	return false
}

// GetTenantRole returns the user's role in a specific tenant.
func (c *Claims) GetTenantRole(tenantID string) string {
	for _, t := range c.Tenants {
		if t.TenantID == tenantID {
			return t.Role
		}
	}
	return ""
}

// HasTenantRole checks if user has a specific role (or higher) in a tenant.
// Role hierarchy: owner > admin > member > viewer
func (c *Claims) HasTenantRole(tenantID string, requiredRole string) bool {
	userRole := c.GetTenantRole(tenantID)
	if userRole == "" {
		return false
	}
	return roleLevel(userRole) >= roleLevel(requiredRole)
}

// GetAccessibleTenantIDs returns all tenant IDs the user has access to.
func (c *Claims) GetAccessibleTenantIDs() []string {
	ids := make([]string, len(c.Tenants))
	for i, t := range c.Tenants {
		ids[i] = t.TenantID
	}
	return ids
}

// roleLevel returns the numeric level of a role for comparison.
// Uses tenant.Role constants for type safety.
func roleLevel(role string) int {
	r := tenant.Role(role)
	return r.Priority()
}

// TokenConfig holds configuration for token generation.
type TokenConfig struct {
	Secret               string
	Issuer               string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

// TokenPair contains both access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// TenantScopedAccessToken contains an access token scoped to a specific tenant.
type TenantScopedAccessToken struct {
	AccessToken string
	TenantID    string
	TenantSlug  string
	Role        string
	ExpiresAt   time.Time
}

// GlobalRefreshTokenResult contains a global refresh token with user's tenant memberships.
type GlobalRefreshTokenResult struct {
	RefreshToken string
	ExpiresAt    time.Time
	Tenants      []TenantMembership
}

// TenantContext holds tenant-specific context for token generation.
type TenantContext struct {
	TenantID    string
	Role        string
	Permissions []string
	IsAdmin     bool
}

// Generator handles JWT token generation and validation.
type Generator struct {
	config TokenConfig
}

// NewGenerator creates a new token generator.
func NewGenerator(config TokenConfig) *Generator {
	return &Generator{config: config}
}

// GenerateAccessToken creates a new access token.
func (g *Generator) GenerateAccessToken(userID, sessionID, role string) (string, time.Time, error) {
	if userID == "" {
		return "", time.Time{}, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: TokenTypeAccess,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// GenerateAccessTokenWithTenant creates an access token with tenant context.
func (g *Generator) GenerateAccessTokenWithTenant(userID, email, sessionID string, tenant TenantContext) (string, time.Time, error) {
	if userID == "" {
		return "", time.Time{}, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	claims := Claims{
		UserID:      userID,
		Email:       email,
		SessionID:   sessionID,
		TokenType:   TokenTypeAccess,
		TenantID:    tenant.TenantID,
		Role:        tenant.Role,
		Permissions: tenant.Permissions,
		IsAdmin:     tenant.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// GenerateRefreshToken creates a new refresh token.
func (g *Generator) GenerateRefreshToken(userID, sessionID string) (string, time.Time, error) {
	if userID == "" {
		return "", time.Time{}, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.RefreshTokenDuration)

	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique jti to prevent token hash collisions
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// GenerateTokenPair creates both access and refresh tokens.
func (g *Generator) GenerateTokenPair(userID, sessionID, role string) (*TokenPair, error) {
	accessToken, expiresAt, err := g.GenerateAccessToken(userID, sessionID, role)
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := g.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// GenerateTokenPairWithTenant creates both access and refresh tokens with tenant context.
func (g *Generator) GenerateTokenPairWithTenant(userID, email, sessionID string, tenant TenantContext) (*TokenPair, error) {
	accessToken, expiresAt, err := g.GenerateAccessTokenWithTenant(userID, email, sessionID, tenant)
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := g.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// GenerateTokenPairWithMemberships creates both access and refresh tokens with all tenant memberships.
// This is the preferred method for multi-tenant authorization.
func (g *Generator) GenerateTokenPairWithMemberships(userID, email, name, sessionID string, tenants []TenantMembership, isAdmin bool) (*TokenPair, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Name:      name,
		SessionID: sessionID,
		TokenType: TokenTypeAccess,
		Tenants:   tenants,
		IsAdmin:   isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := g.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// GenerateGlobalRefreshToken creates a refresh token without any tenant context.
// This is used for the new "global refresh + tenant-scoped access" flow.
// The refresh token only contains user identity, no tenant information.
func (g *Generator) GenerateGlobalRefreshToken(userID, email, name, sessionID string) (string, time.Time, error) {
	if userID == "" {
		return "", time.Time{}, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.RefreshTokenDuration)

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Name:      name,
		SessionID: sessionID,
		TokenType: TokenTypeRefresh,
		// No tenant info - this is a global refresh token
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique jti to prevent token hash collisions
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expiresAt, nil
}

// GenerateTenantScopedAccessToken creates an access token scoped to a specific tenant.
// This token contains only the user's role for the specified tenant.
//
// Permission handling:
// - Owner/Admin (isAdmin=true): No permissions in JWT, bypass all permission checks
// - Member/Viewer/Custom (isAdmin=false): Permissions derived from role and included in JWT
//
// JWT size is kept under 4KB browser cookie limit:
// - Owner/Admin: ~500 bytes (no permissions)
// - Member: ~1.5KB (~42 permissions)
// - Viewer: ~1KB (~25 permissions)
func (g *Generator) GenerateTenantScopedAccessToken(userID, email, name, sessionID string, tenant TenantMembership, isAdmin bool) (*TenantScopedAccessToken, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	// For admin users (owner/admin): no permissions needed - they bypass checks via IsAdmin flag
	// For non-admin users (member/viewer/custom): include permissions from role mapping
	var permissions []string
	if !isAdmin {
		permissions = roleToPermissions(tenant.Role)
	}

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Name:      name,
		SessionID: sessionID,
		TokenType: TokenTypeAccess,
		TenantID:  tenant.TenantID,
		Role:      tenant.Role,
		// Admin: nil (bypass via IsAdmin), Non-admin: permissions from role
		Permissions: permissions,
		IsAdmin:     isAdmin,
		// Include single tenant in Tenants array for backward compatibility
		Tenants: []TenantMembership{tenant},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return nil, err
	}

	return &TenantScopedAccessToken{
		AccessToken: signedToken,
		TenantID:    tenant.TenantID,
		TenantSlug:  tenant.TenantSlug,
		Role:        tenant.Role,
		ExpiresAt:   expiresAt,
	}, nil
}

// GenerateTenantScopedAccessTokenWithPermissions creates an access token with explicit permissions.
// This is used when permissions come from the database (multiple roles system) rather than hardcoded role mappings.
// roles parameter contains the role names (e.g., "owner", "admin", "custom_role") for display purposes.
//
// Permission handling:
// - Owner/Admin (isAdmin=true): No permissions in JWT, bypass all permission checks
// - Member/Viewer/Custom (isAdmin=false): Permissions from database included in JWT
//
// Note: For custom RBAC roles with many permissions, JWT might exceed 4KB.
// In that case, consider limiting permissions or using role-based bypass.
func (g *Generator) GenerateTenantScopedAccessTokenWithPermissions(userID, email, name, sessionID string, tenant TenantMembership, permissions []string, roles []string, isAdmin bool) (*TenantScopedAccessToken, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	// Use primary role for backward compatibility
	primaryRole := tenant.Role
	if len(roles) > 0 {
		primaryRole = roles[0]
	}

	// For admin users (owner/admin): no permissions needed - they bypass checks via IsAdmin flag
	// For non-admin users: include permissions from database
	var jwtPermissions []string
	if !isAdmin && len(permissions) > 0 {
		jwtPermissions = permissions
	}

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Name:      name,
		SessionID: sessionID,
		TokenType: TokenTypeAccess,
		TenantID:  tenant.TenantID,
		Role:      primaryRole, // Primary role for backward compatibility
		// Admin: nil (bypass via IsAdmin), Non-admin: permissions from DB
		Permissions: jwtPermissions,
		IsAdmin:     isAdmin,
		Tenants:     []TenantMembership{tenant},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return nil, err
	}

	return &TenantScopedAccessToken{
		AccessToken: signedToken,
		TenantID:    tenant.TenantID,
		TenantSlug:  tenant.TenantSlug,
		Role:        primaryRole,
		ExpiresAt:   expiresAt,
	}, nil
}

// roleToPermissions converts a role to a list of granular permissions.
// Uses the permission package for centralized role-permission mapping.
// Deprecated: Use RoleService.GetUserPermissions for database-driven permissions.
func roleToPermissions(role string) []string {
	r := tenant.Role(role)
	return permission.GetPermissionStringsForRole(r)
}

// SlimAccessToken contains an access token without embedded permissions.
// Used with the real-time permission sync system.
type SlimAccessToken struct {
	AccessToken string
	TenantID    string
	TenantSlug  string
	Role        string
	PermVersion int
	ExpiresAt   time.Time
}

// GenerateSlimAccessToken creates an access token WITHOUT embedded permissions.
// This is the preferred method for the real-time permission sync system.
//
// Instead of embedding permissions in JWT (which can exceed 4KB cookie limit),
// this method only includes the permission version number. The frontend:
// 1. Stores permissions in localStorage
// 2. Checks version on each API response (X-Permission-Stale header)
// 3. Refreshes permissions when version mismatch detected
//
// Benefits:
// - JWT size is always ~400 bytes (fixed, regardless of permission count)
// - Permissions update in real-time when admin changes roles
// - No browser cookie limit issues
func (g *Generator) GenerateSlimAccessToken(
	userID, email, name, sessionID string,
	tenant TenantMembership,
	permVersion int,
) (*SlimAccessToken, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(g.config.AccessTokenDuration)

	claims := Claims{
		UserID:      userID,
		Email:       email,
		Name:        name,
		SessionID:   sessionID,
		TokenType:   TokenTypeAccess,
		TenantID:    tenant.TenantID,
		Role:        tenant.Role, // For display purposes
		PermVersion: permVersion, // Version for sync, NOT the actual permissions
		// NO Permissions array - fetched from Redis/DB on each request
		// NO IsAdmin flag - all users go through same permission check flow
		Tenants: []TenantMembership{tenant}, // For backward compatibility
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return nil, err
	}

	return &SlimAccessToken{
		AccessToken: signedToken,
		TenantID:    tenant.TenantID,
		TenantSlug:  tenant.TenantSlug,
		Role:        tenant.Role,
		PermVersion: permVersion,
		ExpiresAt:   expiresAt,
	}, nil
}

// ValidateToken validates the token and returns the claims.
func (g *Generator) ValidateToken(tokenString string) (*Claims, error) {
	return ValidateToken(tokenString, g.config.Secret)
}

// ValidateAccessToken validates an access token specifically.
func (g *Generator) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := g.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess && claims.TokenType != "" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token specifically.
func (g *Generator) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := g.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// =============================================================================
// Job Token Types (SEC-C03: JWT-based job authentication)
// =============================================================================
// Job tokens are short-lived, scoped tokens for platform agent job operations.
// They provide defense-in-depth with API key authentication.

// JobTokenScope represents allowed operations for a job token.
type JobTokenScope string

const (
	// JobScopeUpdateStatus allows updating job status (running, progress).
	JobScopeUpdateStatus JobTokenScope = "job:status"
	// JobScopeReportResult allows reporting job results.
	JobScopeReportResult JobTokenScope = "job:result"
	// JobScopeIngestFindings allows ingesting scan findings.
	JobScopeIngestFindings JobTokenScope = "job:ingest"
)

// AllJobScopes returns all available job scopes.
func AllJobScopes() []JobTokenScope {
	return []JobTokenScope{
		JobScopeUpdateStatus,
		JobScopeReportResult,
		JobScopeIngestFindings,
	}
}

// JobTokenClaims represents claims specific to job tokens.
// These are more restrictive than user tokens - tied to a specific job and agent.
type JobTokenClaims struct {
	TokenType TokenType       `json:"token_type"`
	AgentID   string          `json:"agent_id"`           // Platform agent ID
	JobID     string          `json:"job_id"`             // Command/Job ID
	TenantID  string          `json:"tenant_id"`          // Tenant owning the job
	Scopes    []JobTokenScope `json:"scopes"`             // Allowed operations
	JobType   string          `json:"job_type,omitempty"` // scan, collect, etc.

	jwt.RegisteredClaims
}

// HasScope checks if the token has a specific scope.
func (c *JobTokenClaims) HasScope(scope JobTokenScope) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the specified scopes.
func (c *JobTokenClaims) HasAnyScope(scopes ...JobTokenScope) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// JobToken represents a generated job token with metadata.
type JobToken struct {
	Token     string
	AgentID   string
	JobID     string
	TenantID  string
	Scopes    []JobTokenScope
	ExpiresAt time.Time
}

// GenerateJobToken creates a new job token for platform agent job operations.
// This implements SEC-C03: JWT job auth tokens with scopes.
//
// Security properties:
// - Short TTL (job timeout + buffer) to minimize exposure window
// - Scoped to specific job, agent, and tenant
// - Cannot be used for any other purpose than job operations
// - Verified in addition to API key (defense-in-depth)
func (g *Generator) GenerateJobToken(
	agentID, jobID, tenantID, jobType string,
	ttl time.Duration,
	scopes []JobTokenScope,
) (*JobToken, error) {
	if agentID == "" {
		return nil, errors.New("agent_id is required")
	}
	if jobID == "" {
		return nil, errors.New("job_id is required")
	}
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if len(scopes) == 0 {
		scopes = AllJobScopes() // Default to all scopes
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := JobTokenClaims{
		TokenType: TokenTypeJob,
		AgentID:   agentID,
		JobID:     jobID,
		TenantID:  tenantID,
		Scopes:    scopes,
		JobType:   jobType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique jti for token tracking
			Issuer:    g.config.Issuer,
			Subject:   jobID,                     // Job is the subject
			Audience:  jwt.ClaimStrings{agentID}, // Agent is the audience
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign job token: %w", err)
	}

	return &JobToken{
		Token:     signedToken,
		AgentID:   agentID,
		JobID:     jobID,
		TenantID:  tenantID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateJobToken validates a job token and returns its claims.
// Use this to verify job tokens in API handlers.
func (g *Generator) ValidateJobToken(tokenString string) (*JobTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JobTokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(g.config.Secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JobTokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify token type
	if claims.TokenType != TokenTypeJob {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// ValidateJobTokenForJob validates a job token for a specific job and agent.
// This is the recommended validation method as it ensures the token is for the right context.
func (g *Generator) ValidateJobTokenForJob(tokenString, expectedAgentID, expectedJobID string) (*JobTokenClaims, error) {
	claims, err := g.ValidateJobToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify agent matches
	if claims.AgentID != expectedAgentID {
		return nil, fmt.Errorf("%w: agent mismatch", ErrInvalidToken)
	}

	// Verify job matches
	if claims.JobID != expectedJobID {
		return nil, fmt.Errorf("%w: job mismatch", ErrInvalidToken)
	}

	return claims, nil
}

// ValidateJobTokenWithScope validates a job token and checks for a required scope.
func (g *Generator) ValidateJobTokenWithScope(tokenString string, requiredScope JobTokenScope) (*JobTokenClaims, error) {
	claims, err := g.ValidateJobToken(tokenString)
	if err != nil {
		return nil, err
	}

	if !claims.HasScope(requiredScope) {
		return nil, fmt.Errorf("%w: missing required scope %s", ErrInvalidToken, requiredScope)
	}

	return claims, nil
}

// GenerateToken creates a new JWT token with the given claims (legacy support).
func GenerateToken(userID, role, secret string, expiry time.Duration) (string, error) {
	if userID == "" {
		return "", ErrEmptyUserID
	}

	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken validates the token and returns the claims.
func ValidateToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateTokenWithExpiry creates a token that expires at a specific time.
func GenerateTokenWithExpiry(userID, role, secret string, expiresAt time.Time) (string, error) {
	if userID == "" {
		return "", ErrEmptyUserID
	}

	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateShortLivedToken creates a short-lived token for WebSocket authentication.
// This is used when WebSocket connections cannot use httpOnly cookies due to
// cross-origin restrictions (e.g., frontend on port 3000, backend on port 8080).
// The token is passed as a query parameter during WebSocket handshake.
func (g *Generator) GenerateShortLivedToken(userID, tenantID string, ttl time.Duration) (string, error) {
	if userID == "" {
		return "", ErrEmptyUserID
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		TokenType: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.config.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(g.config.Secret))
}
