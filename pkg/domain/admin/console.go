package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Console authentication (RFC-022): human login to the platform admin console
// with a password and a mandatory TOTP second factor, backed by server-side
// sessions. API-key authentication on AdminUser is separate and unchanged.

const (
	// SessionTTL is the absolute lifetime of a verified console session.
	SessionTTL = 8 * time.Hour
	// SessionIdleTimeout ends a verified session that has not been used.
	SessionIdleTimeout = 30 * time.Minute
	// PendingMFATTL is how long a password-verified login may wait for its TOTP.
	PendingMFATTL = 5 * time.Minute
	// MinPasswordLength for console passwords.
	MinPasswordLength = 12
	// MaxPasswordLength keeps passwords within bcrypt's 72-byte input limit.
	MaxPasswordLength = 72
)

// Credentials are an admin's console login secrets. Absent (nil) until the
// admin first sets a password.
type Credentials struct {
	AdminID            shared.ID
	PasswordHash       string
	MFASecretEncrypted string
	MFAEnabled         bool
	MFALastStep        int64
	PasswordChangedAt  *time.Time
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
}

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
	// DeleteCredentials removes password and MFA (credential reset).
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
}

// Console authentication errors. Login failures are deliberately collapsed
// into ErrInvalidCredentials at the HTTP layer so callers cannot tell which
// factor failed or whether the email exists.
var (
	ErrCredentialsNotFound = fmt.Errorf("%w: admin console credentials not set", shared.ErrNotFound)
	ErrSessionNotFound     = fmt.Errorf("%w: admin session not found", shared.ErrNotFound)
	ErrInvalidCredentials  = fmt.Errorf("%w: invalid credentials", shared.ErrUnauthorized)
	ErrInvalidMFACode      = fmt.Errorf("%w: invalid verification code", shared.ErrUnauthorized)
	ErrAccountLocked       = fmt.Errorf("%w: account temporarily locked", shared.ErrForbidden)
	ErrWeakPassword        = fmt.Errorf("%w: password must be %d-%d characters", shared.ErrValidation, MinPasswordLength, MaxPasswordLength)
	ErrCurrentPassword     = fmt.Errorf("%w: current password is incorrect", shared.ErrUnauthorized)
)
