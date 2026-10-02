// Package mfa holds the second-factor (TOTP) state of tenant user accounts:
// the enrolled authenticator secret, the single-use recovery codes and the
// short-lived login challenges issued between the password step and the code
// step.
//
// The platform admin console keeps its own, separate second factor
// (pkg/domain/admin); this package is only for organization users who sign in
// with a local password. Federated (SSO/SAML/OAuth) users get their second
// factor from their identity provider and never touch these tables.
package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// RecoveryCodeCount is how many recovery codes a user receives at once.
	RecoveryCodeCount = 10
	// ChallengeTTL is how long a login challenge stays usable.
	ChallengeTTL = 5 * time.Minute
	// MaxChallengeAttempts is how many codes may be tried against one
	// challenge before it is burned and the user must start over.
	MaxChallengeAttempts = 5
)

// Purpose says what a login challenge is for.
type Purpose string

const (
	// PurposeVerify: the user has 2FA enabled and must present a code.
	PurposeVerify Purpose = "verify"
	// PurposeEnroll: an organization the user belongs to requires 2FA and the
	// user has not enrolled yet; the challenge only allows enrolling.
	PurposeEnroll Purpose = "enroll"
)

// IsValid reports whether p is a known purpose.
func (p Purpose) IsValid() bool { return p == PurposeVerify || p == PurposeEnroll }

var (
	// ErrFactorNotFound: the user has no second-factor row.
	ErrFactorNotFound = fmt.Errorf("%w: mfa factor not found", shared.ErrNotFound)
	// ErrChallengeNotFound: no challenge matches the presented token.
	ErrChallengeNotFound = fmt.Errorf("%w: mfa challenge not found", shared.ErrNotFound)
	// ErrInvalidPurpose: a challenge was created with an unknown purpose.
	ErrInvalidPurpose = errors.New("invalid mfa challenge purpose")
)

// Factor is a user's TOTP enrollment.
type Factor struct {
	UserID shared.ID
	// SecretEncrypted is the active authenticator secret (AES-GCM with the
	// application encryption key). Empty until enrollment is confirmed.
	SecretEncrypted string
	// PendingSecretEncrypted is a secret issued by a setup call that has not
	// been confirmed with a code yet. It never authenticates anything.
	PendingSecretEncrypted string
	PendingCreatedAt       *time.Time
	Enabled                bool
	EnabledAt              *time.Time
	// LastUsedStep is the newest RFC 6238 time step accepted for this user. A
	// code whose step is not greater is a replay and is rejected.
	LastUsedStep int64
}

// RecoveryCode is one stored (hashed) recovery code.
type RecoveryCode struct {
	ID       shared.ID
	UserID   shared.ID
	CodeHash string
	UsedAt   *time.Time
}

// Challenge is the short-lived, single-purpose handle a password login
// returns instead of a session when a second step is needed. Only the SHA-256
// of the token is stored. A challenge is never a session and is never
// accepted as an access token: it is an opaque random string, not a JWT, and
// the only endpoints that read it are the /auth/mfa/* steps.
type Challenge struct {
	ID         shared.ID
	UserID     shared.ID
	TokenHash  string
	Purpose    Purpose
	Attempts   int
	IPAddress  string
	UserAgent  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// Usable reports whether the challenge can still be presented at now.
func (c *Challenge) Usable(now time.Time) bool {
	return c.ConsumedAt == nil && now.Before(c.ExpiresAt) && c.Attempts < MaxChallengeAttempts
}

// Repository persists second-factor state. All methods are keyed by user id;
// none of this is tenant data (a user's second factor is global to the user,
// like their password).
type Repository interface {
	// GetFactor returns the user's factor or ErrFactorNotFound.
	GetFactor(ctx context.Context, userID shared.ID) (*Factor, error)
	// SavePendingSecret stores a not-yet-confirmed secret, creating the row if
	// needed. It never touches an already enabled secret.
	SavePendingSecret(ctx context.Context, userID shared.ID, secretEncrypted string) error
	// Activate promotes the pending secret to active, records step as the last
	// used step and replaces all recovery codes with codeHashes, atomically.
	// It returns false when there was no pending secret to promote (raced with
	// another activation or a disable).
	Activate(ctx context.Context, userID shared.ID, step int64, codeHashes []string) (bool, error)
	// Disable removes the factor and every recovery code.
	Disable(ctx context.Context, userID shared.ID) error
	// AdvanceStep records step as used if and only if it is newer than the
	// last used step. false means the code was already used (replay).
	AdvanceStep(ctx context.Context, userID shared.ID, step int64) (bool, error)

	// ListUnusedRecoveryCodes returns the codes not used yet.
	ListUnusedRecoveryCodes(ctx context.Context, userID shared.ID) ([]RecoveryCode, error)
	// ConsumeRecoveryCode marks a code used if it was unused. false means it
	// had already been used (raced with another request).
	ConsumeRecoveryCode(ctx context.Context, userID, codeID shared.ID) (bool, error)
	// ReplaceRecoveryCodes deletes every code and stores codeHashes instead.
	ReplaceRecoveryCodes(ctx context.Context, userID shared.ID, codeHashes []string) error

	// CreateChallenge stores a new challenge.
	CreateChallenge(ctx context.Context, c *Challenge) error
	// GetChallengeByTokenHash returns the challenge or ErrChallengeNotFound.
	GetChallengeByTokenHash(ctx context.Context, tokenHash string) (*Challenge, error)
	// RecordChallengeAttempt increments the attempt counter and returns the
	// new value.
	RecordChallengeAttempt(ctx context.Context, id shared.ID) (int, error)
	// ConsumeChallenge marks the challenge used if it is unused and unexpired.
	// false means another request already used it.
	ConsumeChallenge(ctx context.Context, id shared.ID) (bool, error)
	// DeleteExpiredChallenges removes challenges past their expiry.
	DeleteExpiredChallenges(ctx context.Context) (int64, error)
}
