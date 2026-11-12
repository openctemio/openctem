// Package admin defines the AdminUser domain entity for platform administration.
// Admin users are platform operators (NOT tenant users) with API key authentication
// and role-based access control for managing platform sensors, bootstrap tokens, and other
// platform-level resources.
package admin

import (
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

	// AdminRoleOpsAdmin can manage sensors, tokens, and view audit logs.
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

// =============================================================================
// Admin User Entity
// =============================================================================

// AdminUser represents a platform administrator (RFC-022): the role, lockout
// and audit identity of a person who signs in on /login with their linked
// users account and opens the console with a TOTP code. Administrators have no
// API keys.
type AdminUser struct {
	id    shared.ID
	email string
	name  string
	role  AdminRole
	// acting is the role this request acts as (ActAs); empty = role.
	acting AdminRole
	// roles, held and perms are the platform roles the administrator holds,
	// what they grant, and what this request acts with (SetPlatformAccess,
	// RFC-134). Authorization reads perms; nil means nothing.
	roles      []platformauthz.RoleKey
	held       platformauthz.Set
	perms      platformauthz.Set
	accessSet  bool
	isActive   bool
	userID     *shared.ID // the linked users account the administrator signs in with
	lastUsedAt *time.Time
	lastUsedIP string

	// Security: Failed login tracking (SEC-H01)
	failedLoginCount  int
	lockedUntil       *time.Time
	lastFailedLoginAt *time.Time
	lastFailedLoginIP string

	createdAt time.Time
	createdBy *shared.ID
	updatedAt time.Time

	signIn SignInState
}

// SignInState is how an administrator may sign in (RFC-022 revision 4).
type SignInState struct {
	// BreakGlass marks a local emergency-access administrator: never bound to
	// the platform IdP, exempt from "require IdP", every sign-in alerted.
	BreakGlass bool
	// BreakGlassTestedAt is when another super admin last confirmed a
	// break-glass sign-in as a test.
	BreakGlassTestedAt *time.Time
	// PasswordChangeRequired is set while the account still has the temporary
	// password it was provisioned with.
	PasswordChangeRequired bool
	// IdPIssuer and IdPSubject bind the administrator to one platform-IdP
	// identity; both empty when unbound.
	IdPIssuer  string
	IdPSubject string
	IdPBoundAt *time.Time
}

// BreakGlassTestInterval is how often a break-glass account should be tested
// (Microsoft's emergency-access guidance: at least every 90 days).
const BreakGlassTestInterval = 90 * 24 * time.Hour

// NewAdminUser creates a new AdminUser entity.
func NewAdminUser(email, name string, role AdminRole, createdBy *shared.ID) (*AdminUser, error) {
	// Validate email
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, shared.NewDomainError("VALIDATION", "email is required", shared.ErrValidation)
	}
	if !strings.Contains(email, "@") {
		return nil, shared.NewDomainError("VALIDATION", "invalid email format", shared.ErrValidation)
	}

	// Validate name
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	// Validate role
	if !role.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid role", shared.ErrValidation)
	}

	now := time.Now()
	admin := &AdminUser{
		id:        shared.NewID(),
		email:     email,
		name:      name,
		role:      role,
		isActive:  true,
		createdAt: now,
		createdBy: createdBy,
		updatedAt: now,
	}

	return admin, nil
}

// Reconstitute creates an AdminUser from database values (no validation).
// Used when loading from the database.
func Reconstitute(
	id shared.ID,
	email, name string,
	role AdminRole,
	isActive bool,
	userID *shared.ID,
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
		role:              role,
		isActive:          isActive,
		userID:            userID,
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

// WithSignInState sets the sign-in state loaded from the database and returns
// the administrator (used by repositories after Reconstitute).
func (a *AdminUser) WithSignInState(s SignInState) *AdminUser {
	a.signIn = s
	return a
}

// SignInState returns how the administrator may sign in.
func (a *AdminUser) SignInState() SignInState { return a.signIn }

// IsBreakGlass reports whether this is a local emergency-access administrator.
func (a *AdminUser) IsBreakGlass() bool { return a.signIn.BreakGlass }

// PasswordChangeRequired reports whether the account still has its temporary password.
func (a *AdminUser) PasswordChangeRequired() bool { return a.signIn.PasswordChangeRequired }

// IdPBound reports whether the administrator is bound to a platform-IdP identity.
func (a *AdminUser) IdPBound() bool { return a.signIn.IdPSubject != "" }

// SetBreakGlass marks or unmarks the administrator as break-glass. A bound
// administrator cannot be break-glass (it would depend on the IdP).
func (a *AdminUser) SetBreakGlass(on bool) error {
	if on && a.IdPBound() {
		return ErrBreakGlassBound
	}
	a.signIn.BreakGlass = on
	a.updatedAt = time.Now()
	return nil
}

// RequirePasswordChange marks the account as holding a temporary password.
func (a *AdminUser) RequirePasswordChange() { a.signIn.PasswordChangeRequired = true }

// BreakGlassTestOverdue reports whether a break-glass account has not been
// tested within BreakGlassTestInterval.
func (a *AdminUser) BreakGlassTestOverdue(now time.Time) bool {
	if !a.signIn.BreakGlass {
		return false
	}
	t := a.signIn.BreakGlassTestedAt
	return t == nil || now.Sub(*t) > BreakGlassTestInterval
}

// =============================================================================
// Getters
// =============================================================================

// ID returns the admin user's ID.
func (a *AdminUser) ID() shared.ID { return a.id }

// Email returns the admin user's email.
func (a *AdminUser) Email() string { return a.email }

// Name returns the admin user's name.
func (a *AdminUser) Name() string { return a.name }

// Role returns the admin user's role.
func (a *AdminUser) Role() AdminRole { return a.role }

// MaxRole is the administrator's own role: the most it may act as.
func (a *AdminUser) MaxRole() AdminRole { return a.role }

// EffectiveRole is the role this request acts as: the elevated or read-only
// role set by ActAs, else the administrator's own. Every authorization check
// uses it; Role (persisted) is the ceiling.
func (a *AdminUser) EffectiveRole() AdminRole {
	if a.acting != "" {
		return a.acting
	}
	return a.role
}

// ActAs restricts this request to role, which never exceeds the
// administrator's own (a higher one is capped at it). It is not persisted.
func (a *AdminUser) ActAs(role AdminRole) {
	if !role.IsValid() || roleRank(role) > roleRank(a.role) {
		role = a.role
	}
	a.acting = role
}

// roleRank orders the roles: readonly < ops_admin < super_admin.
func roleRank(r AdminRole) int {
	switch r {
	case AdminRoleSuperAdmin:
		return 3
	case AdminRoleOpsAdmin:
		return 2
	case AdminRoleReadonly:
		return 1
	}
	return 0
}

// RoleAtMost reports whether r is not above max.
func RoleAtMost(r, max AdminRole) bool { return r.IsValid() && roleRank(r) <= roleRank(max) }

// IsActive returns whether the admin user is active.
func (a *AdminUser) IsActive() bool { return a.isActive }

// SetPlatformAccess records the platform roles the administrator holds and
// the permissions this request acts with. Not persisted.
func (a *AdminUser) SetPlatformAccess(roles []platformauthz.RoleKey, acting platformauthz.Set) {
	a.roles = append([]platformauthz.RoleKey(nil), roles...)
	a.held = platformauthz.Held(roles)
	a.perms = acting
	a.accessSet = true
}

// The console's authentication always records the platform access. An
// administrator loaded without it (a service call outside a console request)
// holds the base role of its tier and acts at its acting tier, as the tiers
// did before platform roles.
func (a *AdminUser) heldSet() platformauthz.Set {
	if a.accessSet {
		return a.held
	}
	return platformauthz.RolePermissions(platformauthz.BaseRoleFor(platformauthz.Tier(a.role)))
}

func (a *AdminUser) actingSet() platformauthz.Set {
	if a.accessSet {
		return a.perms
	}
	return platformauthz.RolePermissions(platformauthz.BaseRoleFor(platformauthz.Tier(a.EffectiveRole())))
}

// Can reports whether this request may use platform permission p: the
// administrator is active and acts with it now (elevation included).
func (a *AdminUser) Can(p platformauthz.Permission) bool {
	return a != nil && a.isActive && a.actingSet().Has(p)
}

// Permissions is what this request acts with.
func (a *AdminUser) Permissions() platformauthz.Set { return a.actingSet() }

// HeldPermissions is everything the administrator's roles grant (the most an
// elevation can reach).
func (a *AdminUser) HeldPermissions() platformauthz.Set { return a.heldSet() }

// PlatformRoles is the platform roles the administrator holds (the tier's
// base role when the access was not recorded).
func (a *AdminUser) PlatformRoles() []platformauthz.RoleKey {
	if a.accessSet {
		return a.roles
	}
	return []platformauthz.RoleKey{platformauthz.BaseRoleFor(platformauthz.Tier(a.role))}
}

// UserID returns the linked users account, or nil for a row that was never
// linked (such rows were deactivated by migration 000227).
func (a *AdminUser) UserID() *shared.ID { return a.userID }

// LastUsedAt returns when the administrator last opened the console.
func (a *AdminUser) LastUsedAt() *time.Time { return a.lastUsedAt }

// LastUsedIP returns the IP the administrator last opened the console from.
func (a *AdminUser) LastUsedIP() string { return a.lastUsedIP }

// CreatedAt returns when the admin user was created.
func (a *AdminUser) CreatedAt() time.Time { return a.createdAt }

// CreatedBy returns who created this admin user.
func (a *AdminUser) CreatedBy() *shared.ID { return a.createdBy }

// UpdatedAt returns when the admin user was last updated.
func (a *AdminUser) UpdatedAt() time.Time { return a.updatedAt }

// =============================================================================
// Authentication Methods
// =============================================================================

const (
	// MaxFailedLoginAttempts is the maximum number of failed login attempts before lockout.
	MaxFailedLoginAttempts = 10

	// LockoutDuration is the duration for which an account is locked after too many failed attempts.
	LockoutDuration = 30 * time.Minute
)

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
