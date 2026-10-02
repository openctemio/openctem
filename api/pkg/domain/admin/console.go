package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Console authentication (RFC-022): an administrator signs in on the normal
// /login page with their users-table account, then opens the console with a
// mandatory TOTP second factor, backed by server-side sessions. API-key
// authentication on AdminUser is separate and unchanged.

const (
	// SessionTTL is the absolute lifetime of a verified console session.
	SessionTTL = 8 * time.Hour
	// SessionIdleTimeout ends a verified session that has not been used.
	SessionIdleTimeout = 30 * time.Minute
	// PendingMFATTL is how long a started console session may wait for its TOTP.
	PendingMFATTL = 5 * time.Minute
)

// Credentials are an admin's console second factor. Absent (nil) until the
// admin first opens the console and is issued a secret to enroll.
type Credentials struct {
	AdminID            shared.ID
	MFASecretEncrypted string
	MFAEnabled         bool
	MFALastStep        int64
}

// Session is a server-side console session. Pending sessions (MFAVerified
// false) only allow completing the TOTP step.
type Session struct {
	ID          shared.ID
	AdminID     shared.ID
	TokenHash   string
	MFAVerified bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastSeenAt  time.Time
	IP          string
	UserAgent   string
	// AuthMethod is how the first factor was proven: AuthMethodPassword (the
	// /login session) or AuthMethodIdP (the platform identity provider).
	AuthMethod string
}

// Console session authentication methods.
const (
	AuthMethodPassword = "password"
	AuthMethodIdP      = "idp"
)

// Usable reports whether a verified session can authenticate a request at now.
func (s *Session) Usable(now time.Time) bool {
	return s.MFAVerified && now.Before(s.ExpiresAt) && now.Sub(s.LastSeenAt) < SessionIdleTimeout
}

// ConsoleRepository persists console credentials and sessions.
type ConsoleRepository interface {
	// GetCredentials returns ErrCredentialsNotFound when none are set.
	GetCredentials(ctx context.Context, adminID shared.ID) (*Credentials, error)
	// SaveCredentials upserts the credentials row.
	SaveCredentials(ctx context.Context, c *Credentials) error
	// DeleteCredentials removes the second factor (reset for a lost authenticator).
	DeleteCredentials(ctx context.Context, adminID shared.ID) error
	// AdvanceMFAStep atomically records step as used, returning false when step
	// is not newer than the last accepted one (a replayed code).
	AdvanceMFAStep(ctx context.Context, adminID shared.ID, step int64) (bool, error)

	CreateSession(ctx context.Context, s *Session) error
	// GetSessionByTokenHash returns ErrSessionNotFound when absent.
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	TouchSession(ctx context.Context, id shared.ID, at time.Time) error
	DeleteSession(ctx context.Context, id shared.ID) error
	// DeleteSessionsForAdmin ends every session of one admin.
	DeleteSessionsForAdmin(ctx context.Context, adminID shared.ID) error
	// DeleteExpiredSessions removes sessions past their absolute expiry.
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
	// DeletePasswordSessionsExceptBreakGlass ends every password-authenticated
	// session of a non-break-glass administrator (when "require IdP" turns on).
	DeletePasswordSessionsExceptBreakGlass(ctx context.Context) (int64, error)
}

// Console authentication errors.
var (
	ErrCredentialsNotFound = fmt.Errorf("%w: admin console credentials not set", shared.ErrNotFound)
	ErrSessionNotFound     = fmt.Errorf("%w: admin session not found", shared.ErrNotFound)
	ErrInvalidCredentials  = fmt.Errorf("%w: invalid credentials", shared.ErrUnauthorized)
	ErrInvalidMFACode      = fmt.Errorf("%w: invalid verification code", shared.ErrUnauthorized)
	ErrAccountLocked       = fmt.Errorf("%w: account temporarily locked", shared.ErrForbidden)
	// ErrNotSignedIn: no valid /login session behind the request.
	ErrNotSignedIn = fmt.Errorf("%w: sign in first", shared.ErrUnauthorized)
	// ErrNotPlatformAdmin: the signed-in account is not an active administrator.
	ErrNotPlatformAdmin = fmt.Errorf("%w: this account is not a platform administrator", shared.ErrForbidden)
	// ErrPasswordSignInRequired: the console opens only from a password sign-in,
	// so an organization's SSO/SAML provider can never authenticate an admin.
	ErrPasswordSignInRequired = fmt.Errorf("%w: platform administrators sign in with their password", shared.ErrForbidden)
	// ErrIdPSignInRequired: "require IdP" is on and this administrator is not
	// break-glass, so the local password path is refused.
	ErrIdPSignInRequired = fmt.Errorf("%w: sign in to the console with the identity provider", shared.ErrForbidden)
	// ErrPasswordChangeRequired: the session may only change the temporary password.
	ErrPasswordChangeRequired = fmt.Errorf("%w: change your temporary password first", shared.ErrForbidden)
)
