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
	// MaxVerifiedSessions caps the verified sessions one administrator may
	// hold at once; opening another ends the oldest.
	MaxVerifiedSessions = 3
	// SessionIdleTimeout ends a verified session that has not been used:
	// 15 minutes, the inactivity bound for the highest authenticator
	// assurance level (the absolute lifetime above stays under its 12 hours).
	SessionIdleTimeout = 15 * time.Minute
	// PendingMFATTL is how long a started console session may wait for its TOTP.
	PendingMFATTL = 5 * time.Minute
	// StepUpWindow is how long one step-up confirmation covers the protected
	// actions of the same console session.
	StepUpWindow = 5 * time.Minute
	// FreshStepUpWindow is how recent a security-key confirmation must be for
	// an action that asks for a fresh check (RequireAdminFreshStepUp). The
	// confirmation is spent by that one action, so it cannot carry a second.
	FreshStepUpWindow = time.Minute
)

type freshStepUpKey struct{}

// WithFreshStepUp marks ctx so that the protected-action check accepts only a
// fresh authenticator code or a just-given, single-use security-key
// confirmation, never the session's step-up window.
func WithFreshStepUp(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshStepUpKey{}, true)
}

// FreshStepUpRequired reports whether ctx was marked by WithFreshStepUp.
func FreshStepUpRequired(ctx context.Context) bool {
	v, _ := ctx.Value(freshStepUpKey{}).(bool)
	return v
}

type backgroundRequestKey struct{}

// WithBackgroundRequest marks ctx as a read the console made on its own (a
// periodic refresh while nobody touches the page). Such a request is
// authenticated as usual but does not count as activity, so an unattended
// tab still reaches SessionIdleTimeout.
func WithBackgroundRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundRequestKey{}, true)
}

// IsBackgroundRequest reports whether ctx was marked by WithBackgroundRequest.
func IsBackgroundRequest(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundRequestKey{}).(bool)
	return v
}

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
	// StepUpAt is when this session last confirmed a protected action with a
	// fresh code; nil when it never did.
	StepUpAt *time.Time
	// EnrollmentRequired is computed on each request, never stored: "require
	// WebAuthn" is on and this administrator has not registered enough
	// authenticators and recovery codes yet, so the session may only enroll.
	EnrollmentRequired bool
	// ElevatedRole and ElevatedUntil: the role this session acts as until
	// then (time-boxed elevation); without them, read-only.
	ElevatedRole  AdminRole
	ElevatedUntil *time.Time
	// PendingIdPIssuer and PendingIdPSubject: on a pending session opened by
	// the first IdP sign-in of an unbound administrator, the IdP identity to
	// bind once this administrator proves their own console second factor.
	// Empty otherwise. An IdP identity is never bound by email alone.
	PendingIdPIssuer  string
	PendingIdPSubject string
}

// Elevation bounds.
const (
	ElevationMin = 15 * time.Minute
	ElevationMax = 60 * time.Minute
)

// ActingRole is the role the session acts as at now: the elevated role while
// the elevation lasts, else read-only.
func (s *Session) ActingRole(now time.Time) AdminRole {
	if s != nil && s.ElevatedUntil != nil && now.Before(*s.ElevatedUntil) && s.ElevatedRole.IsValid() {
		return s.ElevatedRole
	}
	return AdminRoleReadonly
}

// SteppedUp reports whether the session confirmed a protected action within
// StepUpWindow of now.
func (s *Session) SteppedUp(now time.Time) bool {
	return s != nil && s.StepUpAt != nil && !now.Before(*s.StepUpAt) && now.Sub(*s.StepUpAt) < StepUpWindow
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
	// MarkSessionStepUp records a step-up confirmation on a verified session.
	MarkSessionStepUp(ctx context.Context, id shared.ID, at time.Time) error
	// ConsumeSessionStepUp atomically clears the session's step-up mark and
	// reports whether it was set no earlier than notBefore: a security-key
	// confirmation can pay for one fresh action only.
	ConsumeSessionStepUp(ctx context.Context, id shared.ID, notBefore time.Time) (bool, error)
	// SetSessionElevation sets (role non-empty) or ends (role empty) the
	// time-boxed elevation of a verified session.
	SetSessionElevation(ctx context.Context, id shared.ID, role AdminRole, until *time.Time, reason string) error
	DeleteSession(ctx context.Context, id shared.ID) error
	// DeleteSessionsForAdmin ends every session of one admin.
	DeleteSessionsForAdmin(ctx context.Context, adminID shared.ID) error
	// EndOldestVerifiedSessions keeps the newest `keep` verified sessions of
	// one admin and ends the rest, returning how many it ended.
	EndOldestVerifiedSessions(ctx context.Context, adminID shared.ID, keep int) (int64, error)
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
	// ErrStepUpUnavailable: a step-up needs the console's own authenticator, and
	// this administrator has none enrolled (for example, it only ever signed in
	// through the platform identity provider).
	ErrStepUpUnavailable = fmt.Errorf("%w: enroll the console authenticator to confirm this action", shared.ErrForbidden)
	// ErrStepUpRequired: a protected action without a fresh code, outside the
	// session's step-up window.
	ErrStepUpRequired = fmt.Errorf("%w: confirm this action with a fresh code", shared.ErrUnauthorized)
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
