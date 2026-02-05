// Package user provides the user domain model.
package user

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Status represents the user account status.
type Status string

const (
	StatusActive    Status = "active"
	StatusInactive  Status = "inactive"
	StatusSuspended Status = "suspended"
)

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusSuspended:
		return true
	}
	return false
}

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// Preferences represents user preferences stored as JSONB.
type Preferences struct {
	Theme         string `json:"theme,omitempty"`         // "light", "dark", "system"
	Language      string `json:"language,omitempty"`      // "en", "vi"
	Notifications bool   `json:"notifications,omitempty"` // Enable notifications
}

// AuthProvider represents the authentication provider for a user.
type AuthProvider string

const (
	// AuthProviderLocal indicates local email/password authentication.
	AuthProviderLocal AuthProvider = "local"
	// AuthProviderOIDC indicates external OIDC authentication (Keycloak).
	AuthProviderOIDC AuthProvider = "oidc"
	// AuthProviderGoogle indicates Google OAuth authentication.
	AuthProviderGoogle AuthProvider = "google"
	// AuthProviderGitHub indicates GitHub OAuth authentication.
	AuthProviderGitHub AuthProvider = "github"
	// AuthProviderMicrosoft indicates Microsoft/EntraID OAuth authentication.
	AuthProviderMicrosoft AuthProvider = "microsoft"
)

// IsValid checks if the auth provider is valid.
func (p AuthProvider) IsValid() bool {
	switch p {
	case AuthProviderLocal, AuthProviderOIDC, AuthProviderGoogle, AuthProviderGitHub, AuthProviderMicrosoft:
		return true
	}
	return false
}

// IsOAuth returns true if the auth provider is an OAuth provider.
func (p AuthProvider) IsOAuth() bool {
	switch p {
	case AuthProviderGoogle, AuthProviderGitHub, AuthProviderMicrosoft:
		return true
	}
	return false
}

// String returns the string representation of the auth provider.
func (p AuthProvider) String() string {
	return string(p)
}

// User represents a user entity in the domain.
type User struct {
	id          shared.ID
	keycloakID  *string // Nullable for local auth users
	email       string
	name        string
	avatarURL   string
	phone       string
	status      Status
	preferences Preferences
	lastLoginAt *time.Time
	createdAt   time.Time
	updatedAt   time.Time

	// Local auth fields
	authProvider               AuthProvider // "local" or "oidc"
	passwordHash               *string      // Nullable - only for local auth
	emailVerified              bool
	emailVerificationToken     *string
	emailVerificationExpiresAt *time.Time
	passwordResetToken         *string
	passwordResetExpiresAt     *time.Time
	failedLoginAttempts        int
	lockedUntil                *time.Time
}

// NewFromKeycloak creates a new User from Keycloak claims.
func NewFromKeycloak(keycloakID, email, name string) (*User, error) {
	if keycloakID == "" {
		return nil, fmt.Errorf("%w: keycloakID is required", shared.ErrValidation)
	}
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &User{
		id:            shared.NewID(),
		keycloakID:    &keycloakID,
		email:         email,
		name:          name,
		status:        StatusActive,
		preferences:   Preferences{},
		lastLoginAt:   &now,
		createdAt:     now,
		updatedAt:     now,
		authProvider:  AuthProviderOIDC,
		emailVerified: true, // Keycloak handles email verification
	}, nil
}

// New creates a new User without Keycloak (for future standalone auth).
// Deprecated: Use NewLocalUser for local authentication.
func New(email, name string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &User{
		id:           shared.NewID(),
		keycloakID:   nil,
		email:        email,
		name:         name,
		status:       StatusActive,
		preferences:  Preferences{},
		createdAt:    now,
		updatedAt:    now,
		authProvider: AuthProviderLocal,
	}, nil
}

// NewLocalUser creates a new local user with email/password authentication.
func NewLocalUser(email, name, passwordHash string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}
	if passwordHash == "" {
		return nil, fmt.Errorf("%w: password hash is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &User{
		id:            shared.NewID(),
		keycloakID:    nil,
		email:         email,
		name:          name,
		status:        StatusActive,
		preferences:   Preferences{},
		createdAt:     now,
		updatedAt:     now,
		authProvider:  AuthProviderLocal,
		passwordHash:  &passwordHash,
		emailVerified: false, // Requires email verification
	}, nil
}

// NewLocalUserWithID creates a new local user with a specific ID (for syncing from JWT tokens).
// This is used when the user ID already exists in the JWT but not in the database.
func NewLocalUserWithID(id shared.ID, email, name string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &User{
		id:            id,
		keycloakID:    nil,
		email:         email,
		name:          name,
		status:        StatusActive,
		preferences:   Preferences{},
		lastLoginAt:   &now,
		createdAt:     now,
		updatedAt:     now,
		authProvider:  AuthProviderLocal,
		emailVerified: true, // Trust the JWT
	}, nil
}

// NewOAuthUser creates a new user from OAuth provider (Google, GitHub, Microsoft).
func NewOAuthUser(email, name, avatarURL string, provider AuthProvider) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}
	if !provider.IsOAuth() {
		return nil, fmt.Errorf("%w: invalid OAuth provider: %s", shared.ErrValidation, provider)
	}

	now := time.Now().UTC()
	return &User{
		id:            shared.NewID(),
		keycloakID:    nil,
		email:         email,
		name:          name,
		avatarURL:     avatarURL,
		status:        StatusActive,
		preferences:   Preferences{},
		lastLoginAt:   &now,
		createdAt:     now,
		updatedAt:     now,
		authProvider:  provider,
		emailVerified: true, // OAuth providers verify email
	}, nil
}

// Reconstitute recreates a User from persistence.
func Reconstitute(
	id shared.ID,
	keycloakID *string,
	email, name, avatarURL, phone string,
	status Status,
	preferences Preferences,
	lastLoginAt *time.Time,
	createdAt, updatedAt time.Time,
	// Auth fields
	authProvider AuthProvider,
	passwordHash *string,
	emailVerified bool,
	emailVerificationToken *string,
	emailVerificationExpiresAt *time.Time,
	passwordResetToken *string,
	passwordResetExpiresAt *time.Time,
	failedLoginAttempts int,
	lockedUntil *time.Time,
) *User {
	return &User{
		id:                         id,
		keycloakID:                 keycloakID,
		email:                      email,
		name:                       name,
		avatarURL:                  avatarURL,
		phone:                      phone,
		status:                     status,
		preferences:                preferences,
		lastLoginAt:                lastLoginAt,
		createdAt:                  createdAt,
		updatedAt:                  updatedAt,
		authProvider:               authProvider,
		passwordHash:               passwordHash,
		emailVerified:              emailVerified,
		emailVerificationToken:     emailVerificationToken,
		emailVerificationExpiresAt: emailVerificationExpiresAt,
		passwordResetToken:         passwordResetToken,
		passwordResetExpiresAt:     passwordResetExpiresAt,
		failedLoginAttempts:        failedLoginAttempts,
		lockedUntil:                lockedUntil,
	}
}

// ID returns the user ID.
func (u *User) ID() shared.ID {
	return u.id
}

// KeycloakID returns the Keycloak user ID (may be nil).
func (u *User) KeycloakID() *string {
	return u.keycloakID
}

// Email returns the user email.
func (u *User) Email() string {
	return u.email
}

// Name returns the user name.
func (u *User) Name() string {
	return u.name
}

// AvatarURL returns the user avatar URL.
func (u *User) AvatarURL() string {
	return u.avatarURL
}

// Phone returns the user phone number.
func (u *User) Phone() string {
	return u.phone
}

// Status returns the user status.
func (u *User) Status() Status {
	return u.status
}

// Preferences returns the user preferences.
func (u *User) Preferences() Preferences {
	return u.preferences
}

// LastLoginAt returns the last login timestamp.
func (u *User) LastLoginAt() *time.Time {
	return u.lastLoginAt
}

// CreatedAt returns the creation timestamp.
func (u *User) CreatedAt() time.Time {
	return u.createdAt
}

// UpdatedAt returns the last update timestamp.
func (u *User) UpdatedAt() time.Time {
	return u.updatedAt
}

// UpdateProfile updates the user profile.
func (u *User) UpdateProfile(name, phone, avatarURL string) {
	u.name = name
	u.phone = phone
	u.avatarURL = avatarURL
	u.updatedAt = time.Now().UTC()
}

// UpdateEmail updates the user email.
func (u *User) UpdateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", shared.ErrValidation)
	}
	u.email = email
	u.updatedAt = time.Now().UTC()
	return nil
}

// UpdatePreferences updates the user preferences.
func (u *User) UpdatePreferences(prefs Preferences) {
	u.preferences = prefs
	u.updatedAt = time.Now().UTC()
}

// UpdateLastLogin updates the last login timestamp to now.
func (u *User) UpdateLastLogin() {
	now := time.Now().UTC()
	u.lastLoginAt = &now
	u.updatedAt = now
}

// SyncFromKeycloak updates user info from Keycloak claims.
func (u *User) SyncFromKeycloak(email, name string) {
	if email != "" && email != u.email {
		u.email = email
	}
	if name != "" && name != u.name {
		u.name = name
	}
	u.UpdateLastLogin()
}

// Suspend suspends the user account.
func (u *User) Suspend() error {
	if u.status == StatusSuspended {
		return fmt.Errorf("%w: user is already suspended", shared.ErrValidation)
	}
	u.status = StatusSuspended
	u.updatedAt = time.Now().UTC()
	return nil
}

// Activate activates the user account.
func (u *User) Activate() error {
	if u.status == StatusActive {
		return fmt.Errorf("%w: user is already active", shared.ErrValidation)
	}
	u.status = StatusActive
	u.updatedAt = time.Now().UTC()
	return nil
}

// Deactivate deactivates the user account.
func (u *User) Deactivate() error {
	if u.status == StatusInactive {
		return fmt.Errorf("%w: user is already inactive", shared.ErrValidation)
	}
	u.status = StatusInactive
	u.updatedAt = time.Now().UTC()
	return nil
}

// IsActive returns true if the user is active.
func (u *User) IsActive() bool {
	return u.status == StatusActive
}

// IsSuspended returns true if the user is suspended.
func (u *User) IsSuspended() bool {
	return u.status == StatusSuspended
}

// =============================================================================
// Local Auth Getters
// =============================================================================

// AuthProvider returns the authentication provider.
func (u *User) AuthProvider() AuthProvider {
	return u.authProvider
}

// PasswordHash returns the password hash (nil for OIDC users).
func (u *User) PasswordHash() *string {
	return u.passwordHash
}

// EmailVerified returns whether the email is verified.
func (u *User) EmailVerified() bool {
	return u.emailVerified
}

// EmailVerificationToken returns the email verification token.
func (u *User) EmailVerificationToken() *string {
	return u.emailVerificationToken
}

// EmailVerificationExpiresAt returns when the verification token expires.
func (u *User) EmailVerificationExpiresAt() *time.Time {
	return u.emailVerificationExpiresAt
}

// PasswordResetToken returns the password reset token.
func (u *User) PasswordResetToken() *string {
	return u.passwordResetToken
}

// PasswordResetExpiresAt returns when the password reset token expires.
func (u *User) PasswordResetExpiresAt() *time.Time {
	return u.passwordResetExpiresAt
}

// FailedLoginAttempts returns the number of failed login attempts.
func (u *User) FailedLoginAttempts() int {
	return u.failedLoginAttempts
}

// LockedUntil returns when the account lockout expires.
func (u *User) LockedUntil() *time.Time {
	return u.lockedUntil
}

// =============================================================================
// Local Auth Methods
// =============================================================================

// IsLocalUser returns true if this is a local auth user.
func (u *User) IsLocalUser() bool {
	return u.authProvider == AuthProviderLocal
}

// IsOIDCUser returns true if this is an OIDC auth user.
func (u *User) IsOIDCUser() bool {
	return u.authProvider == AuthProviderOIDC
}

// IsLocked returns true if the account is currently locked.
func (u *User) IsLocked() bool {
	if u.lockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.lockedUntil)
}

// CanLogin returns true if the user can attempt to login.
func (u *User) CanLogin() bool {
	return u.IsActive() && !u.IsLocked()
}

// SetPasswordHash sets the password hash for local auth users.
func (u *User) SetPasswordHash(hash string) error {
	if u.authProvider != AuthProviderLocal {
		return fmt.Errorf("%w: cannot set password for OIDC users", shared.ErrValidation)
	}
	u.passwordHash = &hash
	u.updatedAt = time.Now().UTC()
	return nil
}

// VerifyEmail marks the email as verified.
func (u *User) VerifyEmail() {
	u.emailVerified = true
	u.emailVerificationToken = nil
	u.emailVerificationExpiresAt = nil
	u.updatedAt = time.Now().UTC()
}

// SetEmailVerificationToken sets a new email verification token.
func (u *User) SetEmailVerificationToken(token string, expiresAt time.Time) {
	u.emailVerificationToken = &token
	u.emailVerificationExpiresAt = &expiresAt
	u.emailVerified = false
	u.updatedAt = time.Now().UTC()
}

// IsEmailVerificationTokenValid returns true if the verification token is valid.
func (u *User) IsEmailVerificationTokenValid(token string) bool {
	if u.emailVerificationToken == nil || u.emailVerificationExpiresAt == nil {
		return false
	}
	if *u.emailVerificationToken != token {
		return false
	}
	return time.Now().Before(*u.emailVerificationExpiresAt)
}

// SetPasswordResetToken sets a new password reset token.
func (u *User) SetPasswordResetToken(token string, expiresAt time.Time) {
	u.passwordResetToken = &token
	u.passwordResetExpiresAt = &expiresAt
	u.updatedAt = time.Now().UTC()
}

// ClearPasswordResetToken clears the password reset token.
func (u *User) ClearPasswordResetToken() {
	u.passwordResetToken = nil
	u.passwordResetExpiresAt = nil
	u.updatedAt = time.Now().UTC()
}

// IsPasswordResetTokenValid returns true if the reset token is valid.
func (u *User) IsPasswordResetTokenValid(token string) bool {
	if u.passwordResetToken == nil || u.passwordResetExpiresAt == nil {
		return false
	}
	if *u.passwordResetToken != token {
		return false
	}
	return time.Now().Before(*u.passwordResetExpiresAt)
}

// RecordFailedLogin increments the failed login counter.
func (u *User) RecordFailedLogin(maxAttempts int, lockoutDuration time.Duration) {
	u.failedLoginAttempts++
	if u.failedLoginAttempts >= maxAttempts {
		lockUntil := time.Now().Add(lockoutDuration)
		u.lockedUntil = &lockUntil
	}
	u.updatedAt = time.Now().UTC()
}

// RecordSuccessfulLogin clears failed login attempts and updates last login.
func (u *User) RecordSuccessfulLogin() {
	u.failedLoginAttempts = 0
	u.lockedUntil = nil
	u.UpdateLastLogin()
}

// Unlock unlocks the user account.
func (u *User) Unlock() {
	u.lockedUntil = nil
	u.failedLoginAttempts = 0
	u.updatedAt = time.Now().UTC()
}
