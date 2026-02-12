// Package admin defines the AdminUser domain entity for platform administration.
// Admin users are platform operators (NOT tenant users) with API key authentication
// and role-based access control for managing platform agents, bootstrap tokens, and other
// platform-level resources.
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Admin Role Value Object
// =============================================================================

// AdminRole represents the role of an admin user.
// Follows simple RBAC with three levels.
type AdminRole string

const (
	// AdminRoleSuperAdmin has full access to all platform operations.
	// Can manage other admin users.
	AdminRoleSuperAdmin AdminRole = "super_admin"

	// AdminRoleOpsAdmin can manage agents, tokens, and view audit logs.
	// Cannot manage other admin users.
	AdminRoleOpsAdmin AdminRole = "ops_admin"

	// AdminRoleReadonly can only view platform resources.
	// No write/modify operations.
	AdminRoleReadonly AdminRole = "readonly"
)

// IsValid checks if the admin role is valid.
func (r AdminRole) IsValid() bool {
	switch r {
	case AdminRoleSuperAdmin, AdminRoleOpsAdmin, AdminRoleReadonly:
		return true
	}
	return false
}

// String returns the string representation of the role.
func (r AdminRole) String() string {
	return string(r)
}

// DisplayName returns a human-readable name for the role.
func (r AdminRole) DisplayName() string {
	switch r {
	case AdminRoleSuperAdmin:
		return "Super Admin"
	case AdminRoleOpsAdmin:
		return "Operations Admin"
	case AdminRoleReadonly:
		return "Read Only"
	default:
		return string(r)
	}
}

// CanManageAdmins checks if this role can manage other admin users.
func (r AdminRole) CanManageAdmins() bool {
	return r == AdminRoleSuperAdmin
}

// CanManageAgents checks if this role can manage platform agents.
func (r AdminRole) CanManageAgents() bool {
	return r == AdminRoleSuperAdmin || r == AdminRoleOpsAdmin
}

// CanManageTokens checks if this role can manage bootstrap tokens.
func (r AdminRole) CanManageTokens() bool {
	return r == AdminRoleSuperAdmin || r == AdminRoleOpsAdmin
}

// CanViewAuditLogs checks if this role can view audit logs.
func (r AdminRole) CanViewAuditLogs() bool {
	return r == AdminRoleSuperAdmin || r == AdminRoleOpsAdmin || r == AdminRoleReadonly
}

// CanCancelJobs checks if this role can cancel platform jobs.
func (r AdminRole) CanCancelJobs() bool {
	return r == AdminRoleSuperAdmin || r == AdminRoleOpsAdmin
}

// =============================================================================
// Admin User Entity
// =============================================================================

const (
	// APIKeyLength is the length of generated API keys in bytes (31 bytes = 248 bits).
	// Combined with "oc-admin-" prefix (9 bytes), total is 71 bytes which fits
	// within bcrypt's 72-byte input limit (Go 1.24+ enforces this strictly).
	APIKeyLength = 31

	// APIKeyPrefix is the prefix for admin API keys.
	APIKeyPrefix = "oc-admin-"

	// BcryptCost is the bcrypt cost factor for API key hashing.
	// Cost of 12 provides good security while keeping auth under 1 second.
	BcryptCost = 12
)

// AdminUser represents a platform administrator.
// Uses private fields for sensitive data with controlled access via getters.
type AdminUser struct {
	id           shared.ID
	email        string
	name         string
	apiKeyHash   string // bcrypt hash - NEVER exposed via getter
	apiKeyPrefix string // First chars for identification (oc-admin-xxx)
	role         AdminRole
	isActive     bool
	lastUsedAt   *time.Time
	lastUsedIP   string

	// Security: Failed login tracking (SEC-H01)
	failedLoginCount  int
	lockedUntil       *time.Time
	lastFailedLoginAt *time.Time
	lastFailedLoginIP string

	createdAt time.Time
	createdBy *shared.ID
	updatedAt time.Time
}

// NewAdminUser creates a new AdminUser entity with a generated API key.
// Returns the admin user, the raw API key (only shown once!), and any error.
// The raw API key must be securely transmitted to the admin and never stored.
func NewAdminUser(email, name string, role AdminRole, createdBy *shared.ID) (*AdminUser, string, error) {
	// Validate email
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, "", shared.NewDomainError("VALIDATION", "email is required", shared.ErrValidation)
	}
	if !strings.Contains(email, "@") {
		return nil, "", shared.NewDomainError("VALIDATION", "invalid email format", shared.ErrValidation)
	}

	// Validate name
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	// Validate role
	if !role.IsValid() {
		return nil, "", shared.NewDomainError("VALIDATION", "invalid role", shared.ErrValidation)
	}

	// Generate API key
	rawKey, hash, prefix, err := generateAPIKey()
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	admin := &AdminUser{
		id:           shared.NewID(),
		email:        email,
		name:         name,
		apiKeyHash:   hash,
		apiKeyPrefix: prefix,
		role:         role,
		isActive:     true,
		createdAt:    now,
		createdBy:    createdBy,
		updatedAt:    now,
	}

	return admin, rawKey, nil
}

// Reconstitute creates an AdminUser from database values (no validation).
// Used when loading from the database.
func Reconstitute(
	id shared.ID,
	email, name string,
	apiKeyHash, apiKeyPrefix string,
	role AdminRole,
	isActive bool,
	lastUsedAt *time.Time,
	lastUsedIP string,
	failedLoginCount int,
	lockedUntil *time.Time,
	lastFailedLoginAt *time.Time,
	lastFailedLoginIP string,
	createdAt time.Time,
	createdBy *shared.ID,
	updatedAt time.Time,
) *AdminUser {
	return &AdminUser{
		id:                id,
		email:             email,
		name:              name,
		apiKeyHash:        apiKeyHash,
		apiKeyPrefix:      apiKeyPrefix,
		role:              role,
		isActive:          isActive,
		lastUsedAt:        lastUsedAt,
		lastUsedIP:        lastUsedIP,
		failedLoginCount:  failedLoginCount,
		lockedUntil:       lockedUntil,
		lastFailedLoginAt: lastFailedLoginAt,
		lastFailedLoginIP: lastFailedLoginIP,
		createdAt:         createdAt,
		createdBy:         createdBy,
		updatedAt:         updatedAt,
	}
}

// =============================================================================
// Getters (NO getter for apiKeyHash - security)
// =============================================================================

// ID returns the admin user's ID.
func (a *AdminUser) ID() shared.ID { return a.id }

// Email returns the admin user's email.
func (a *AdminUser) Email() string { return a.email }

// Name returns the admin user's name.
func (a *AdminUser) Name() string { return a.name }

// APIKeyPrefix returns the API key prefix for identification in logs.
func (a *AdminUser) APIKeyPrefix() string { return a.apiKeyPrefix }

// Role returns the admin user's role.
func (a *AdminUser) Role() AdminRole { return a.role }

// IsActive returns whether the admin user is active.
func (a *AdminUser) IsActive() bool { return a.isActive }

// LastUsedAt returns when the admin user last used their API key.
func (a *AdminUser) LastUsedAt() *time.Time { return a.lastUsedAt }

// LastUsedIP returns the IP from which the admin user last used their API key.
func (a *AdminUser) LastUsedIP() string { return a.lastUsedIP }

// CreatedAt returns when the admin user was created.
func (a *AdminUser) CreatedAt() time.Time { return a.createdAt }

// CreatedBy returns who created this admin user.
func (a *AdminUser) CreatedBy() *shared.ID { return a.createdBy }

// UpdatedAt returns when the admin user was last updated.
func (a *AdminUser) UpdatedAt() time.Time { return a.updatedAt }

// APIKeyHash returns the API key hash for database storage.
// NOTE: This is needed for repository operations but should NOT be exposed via API.
func (a *AdminUser) APIKeyHash() string { return a.apiKeyHash }

// =============================================================================
// Authentication Methods
// =============================================================================

const (
	// MaxFailedLoginAttempts is the maximum number of failed login attempts before lockout.
	MaxFailedLoginAttempts = 10

	// LockoutDuration is the duration for which an account is locked after too many failed attempts.
	LockoutDuration = 30 * time.Minute
)

// VerifyAPIKey verifies if the provided raw API key matches this admin's key.
// Uses bcrypt comparison which is constant-time by design.
func (a *AdminUser) VerifyAPIKey(rawKey string) bool {
	// bcrypt.CompareHashAndPassword handles constant-time comparison internally
	err := bcrypt.CompareHashAndPassword([]byte(a.apiKeyHash), []byte(rawKey))
	return err == nil
}

// CanAuthenticate checks if this admin can authenticate.
// Returns false if the account is locked or inactive.
func (a *AdminUser) CanAuthenticate() bool {
	if !a.isActive {
		return false
	}

	// Check if account is locked
	if a.IsLocked() {
		return false
	}

	return true
}

// IsLocked checks if the account is currently locked due to failed login attempts.
func (a *AdminUser) IsLocked() bool {
	if a.lockedUntil == nil {
		return false
	}
	return time.Now().Before(*a.lockedUntil)
}

// LockoutRemainingTime returns the remaining lockout time, or 0 if not locked.
func (a *AdminUser) LockoutRemainingTime() time.Duration {
	if a.lockedUntil == nil {
		return 0
	}
	remaining := time.Until(*a.lockedUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RecordFailedLogin records a failed login attempt and locks the account if necessary.
func (a *AdminUser) RecordFailedLogin(ip string) {
	now := time.Now()
	a.failedLoginCount++
	a.lastFailedLoginAt = &now
	a.lastFailedLoginIP = ip
	a.updatedAt = now

	// Lock account after max failed attempts
	if a.failedLoginCount >= MaxFailedLoginAttempts {
		lockUntil := now.Add(LockoutDuration)
		a.lockedUntil = &lockUntil
	}
}

// ResetFailedLogins resets the failed login counter (called on successful login).
func (a *AdminUser) ResetFailedLogins() {
	a.failedLoginCount = 0
	a.lockedUntil = nil
	a.updatedAt = time.Now()
}

// RecordUsage records API key usage (IP and timestamp).
func (a *AdminUser) RecordUsage(ip string) {
	now := time.Now()
	a.lastUsedAt = &now
	a.lastUsedIP = ip
	a.updatedAt = now
}

// FailedLoginCount returns the current failed login count.
func (a *AdminUser) FailedLoginCount() int { return a.failedLoginCount }

// LockedUntil returns when the account lockout expires (nil if not locked).
func (a *AdminUser) LockedUntil() *time.Time { return a.lockedUntil }

// LastFailedLoginAt returns when the last failed login occurred.
func (a *AdminUser) LastFailedLoginAt() *time.Time { return a.lastFailedLoginAt }

// LastFailedLoginIP returns the IP of the last failed login attempt.
func (a *AdminUser) LastFailedLoginIP() string { return a.lastFailedLoginIP }

// =============================================================================
// Authorization Methods
// =============================================================================

// HasPermission checks if the admin has permission for a specific action.
func (a *AdminUser) HasPermission(action string) bool {
	if !a.isActive {
		return false
	}

	switch action {
	// Admin management
	case "admin:create", "admin:update", "admin:delete", "admin:list":
		return a.role.CanManageAdmins()

	// Agent management
	case "agent:create", "agent:update", "agent:delete", "agent:disable", "agent:enable":
		return a.role.CanManageAgents()
	case "agent:list", "agent:get", "agent:stats":
		return true // All roles can view

	// Token management
	case "token:create", "token:revoke", "token:delete":
		return a.role.CanManageTokens()
	case "token:list", "token:get":
		return true // All roles can view

	// Job management
	case "job:cancel":
		return a.role.CanCancelJobs()
	case "job:list", "job:get", "job:stats":
		return true // All roles can view

	// Audit logs
	case "audit:list", "audit:get":
		return a.role.CanViewAuditLogs()

	default:
		return false
	}
}

// =============================================================================
// State Mutation Methods
// =============================================================================

// Activate activates the admin user.
func (a *AdminUser) Activate() {
	a.isActive = true
	a.updatedAt = time.Now()
}

// Deactivate deactivates the admin user.
func (a *AdminUser) Deactivate() {
	a.isActive = false
	a.updatedAt = time.Now()
}

// UpdateName updates the admin user's name.
func (a *AdminUser) UpdateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	a.name = name
	a.updatedAt = time.Now()
	return nil
}

// UpdateEmail updates the admin user's email.
func (a *AdminUser) UpdateEmail(email string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return shared.NewDomainError("VALIDATION", "email is required", shared.ErrValidation)
	}
	if !strings.Contains(email, "@") {
		return shared.NewDomainError("VALIDATION", "invalid email format", shared.ErrValidation)
	}
	a.email = email
	a.updatedAt = time.Now()
	return nil
}

// UpdateRole updates the admin user's role.
func (a *AdminUser) UpdateRole(role AdminRole) error {
	if !role.IsValid() {
		return shared.NewDomainError("VALIDATION", "invalid role", shared.ErrValidation)
	}
	a.role = role
	a.updatedAt = time.Now()
	return nil
}

// RotateAPIKey generates a new API key for the admin user.
// Returns the new raw API key (only shown once!).
func (a *AdminUser) RotateAPIKey() (string, error) {
	rawKey, hash, prefix, err := generateAPIKey()
	if err != nil {
		return "", err
	}

	a.apiKeyHash = hash
	a.apiKeyPrefix = prefix
	a.updatedAt = time.Now()

	return rawKey, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// generateAPIKey generates a new API key with bcrypt hash and prefix.
// Returns: rawKey, bcryptHash, prefix, error
//
// Security (SEC-C01): Uses bcrypt with cost factor 12 instead of SHA-256.
// Bcrypt is designed for password/key hashing and is resistant to GPU attacks.
func generateAPIKey() (string, string, string, error) {
	// Generate random bytes (256 bits of entropy - SEC-C02)
	keyBytes := make([]byte, APIKeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", "", shared.NewDomainError("INTERNAL", "failed to generate API key", shared.ErrInternal)
	}

	// Create the full key with prefix
	rawKey := APIKeyPrefix + hex.EncodeToString(keyBytes)

	// Hash for storage using bcrypt (instead of SHA-256)
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(rawKey), BcryptCost)
	if err != nil {
		return "", "", "", shared.NewDomainError("INTERNAL", "failed to hash API key", shared.ErrInternal)
	}

	// Prefix for identification (oc-admin- + first 8 hex chars)
	prefix := rawKey[:len(APIKeyPrefix)+8]

	return rawKey, string(hashBytes), prefix, nil
}

// ExtractAPIKeyPrefix extracts the prefix from a raw API key for lookup.
// Returns empty string if the key format is invalid.
func ExtractAPIKeyPrefix(rawKey string) string {
	if strings.HasPrefix(rawKey, APIKeyPrefix) {
		if len(rawKey) < len(APIKeyPrefix)+8 {
			return ""
		}
		return rawKey[:len(APIKeyPrefix)+8]
	}

	return ""
}

// HashAPIKeyBcrypt hashes a raw API key using bcrypt.
// This should be used for new keys; existing SHA-256 hashes are verified differently.
func HashAPIKeyBcrypt(rawKey string) (string, error) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(rawKey), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hashBytes), nil
}

// GenerateAPIKey generates a new API key.
// Returns the raw key string.
func GenerateAPIKey() (string, error) {
	rawKey, _, _, err := generateAPIKey()
	if err != nil {
		return "", err
	}
	return rawKey, nil
}

// DeriveNameFromEmail derives a display name from an email address.
// E.g., "john.doe@example.com" -> "John Doe"
func DeriveNameFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 0 {
		return email
	}
	name := parts[0]
	// Replace dots and underscores with spaces
	name = strings.ReplaceAll(name, ".", " ")
	name = strings.ReplaceAll(name, "_", " ")
	// Title case
	words := strings.Fields(name)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

// RoleViewer is an alias for AdminRoleReadonly for API compatibility
const RoleViewer AdminRole = AdminRoleReadonly
