package session

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RefreshToken represents a refresh token for session renewal.
// Implements token rotation with family tracking for replay attack detection.
type RefreshToken struct {
	id        shared.ID
	userID    shared.ID
	sessionID shared.ID
	tokenHash string    // SHA256 hash of the actual token
	family    shared.ID // Token family for rotation tracking
	expiresAt time.Time
	usedAt    *time.Time // When the token was used (for rotation)
	revokedAt *time.Time // When the token was revoked
	createdAt time.Time
}

// NewRefreshToken creates a new refresh token.
func NewRefreshToken(
	userID shared.ID,
	sessionID shared.ID,
	token string,
	duration time.Duration,
) (*RefreshToken, error) {
	if userID.IsZero() {
		return nil, shared.ErrValidation
	}
	if sessionID.IsZero() {
		return nil, shared.ErrValidation
	}
	if token == "" {
		return nil, shared.ErrValidation
	}

	now := time.Now()
	return &RefreshToken{
		id:        shared.NewID(),
		userID:    userID,
		sessionID: sessionID,
		tokenHash: hashToken(token),
		family:    shared.NewID(), // New family for new token chain
		expiresAt: now.Add(duration),
		createdAt: now,
	}, nil
}

// NewRefreshTokenInFamily creates a new refresh token in an existing family (rotation).
func NewRefreshTokenInFamily(
	userID shared.ID,
	sessionID shared.ID,
	token string,
	family shared.ID,
	duration time.Duration,
) (*RefreshToken, error) {
	if userID.IsZero() {
		return nil, shared.ErrValidation
	}
	if sessionID.IsZero() {
		return nil, shared.ErrValidation
	}
	if token == "" {
		return nil, shared.ErrValidation
	}
	if family.IsZero() {
		return nil, shared.ErrValidation
	}

	now := time.Now()
	return &RefreshToken{
		id:        shared.NewID(),
		userID:    userID,
		sessionID: sessionID,
		tokenHash: hashToken(token),
		family:    family,
		expiresAt: now.Add(duration),
		createdAt: now,
	}, nil
}

// ReconstituteRefreshToken creates a refresh token from persisted data.
func ReconstituteRefreshToken(
	id shared.ID,
	userID shared.ID,
	sessionID shared.ID,
	tokenHash string,
	family shared.ID,
	expiresAt time.Time,
	usedAt *time.Time,
	revokedAt *time.Time,
	createdAt time.Time,
) *RefreshToken {
	return &RefreshToken{
		id:        id,
		userID:    userID,
		sessionID: sessionID,
		tokenHash: tokenHash,
		family:    family,
		expiresAt: expiresAt,
		usedAt:    usedAt,
		revokedAt: revokedAt,
		createdAt: createdAt,
	}
}

// Getters

// ID returns the refresh token ID.
func (rt *RefreshToken) ID() shared.ID {
	return rt.id
}

// UserID returns the user ID.
func (rt *RefreshToken) UserID() shared.ID {
	return rt.userID
}

// SessionID returns the associated session ID.
func (rt *RefreshToken) SessionID() shared.ID {
	return rt.sessionID
}

// TokenHash returns the hash of the token.
func (rt *RefreshToken) TokenHash() string {
	return rt.tokenHash
}

// Family returns the token family ID.
func (rt *RefreshToken) Family() shared.ID {
	return rt.family
}

// ExpiresAt returns when the token expires.
func (rt *RefreshToken) ExpiresAt() time.Time {
	return rt.expiresAt
}

// UsedAt returns when the token was used.
func (rt *RefreshToken) UsedAt() *time.Time {
	return rt.usedAt
}

// RevokedAt returns when the token was revoked.
func (rt *RefreshToken) RevokedAt() *time.Time {
	return rt.revokedAt
}

// CreatedAt returns when the token was created.
func (rt *RefreshToken) CreatedAt() time.Time {
	return rt.createdAt
}

// Domain methods

// IsExpired returns true if the token has expired.
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.expiresAt)
}

// IsUsed returns true if the token has been used.
func (rt *RefreshToken) IsUsed() bool {
	return rt.usedAt != nil
}

// IsRevoked returns true if the token has been revoked.
func (rt *RefreshToken) IsRevoked() bool {
	return rt.revokedAt != nil
}

// IsValid returns true if the token is valid (not expired, used, or revoked).
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsExpired() && !rt.IsUsed() && !rt.IsRevoked()
}

// VerifyToken verifies if the provided token matches this refresh token.
func (rt *RefreshToken) VerifyToken(token string) bool {
	return rt.tokenHash == hashToken(token)
}

// MarkUsed marks the token as used.
func (rt *RefreshToken) MarkUsed() error {
	if rt.IsUsed() {
		return ErrRefreshTokenUsed
	}
	if rt.IsRevoked() {
		return ErrRefreshTokenRevoked
	}
	if rt.IsExpired() {
		return ErrRefreshTokenExpired
	}
	now := time.Now()
	rt.usedAt = &now
	return nil
}

// Revoke marks the token as revoked.
func (rt *RefreshToken) Revoke() error {
	if rt.IsRevoked() {
		return ErrRefreshTokenRevoked
	}
	now := time.Now()
	rt.revokedAt = &now
	return nil
}
