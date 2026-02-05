package session

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository defines the interface for session persistence.
type Repository interface {
	// Create creates a new session.
	Create(ctx context.Context, session *Session) error

	// GetByID retrieves a session by its ID.
	GetByID(ctx context.Context, id shared.ID) (*Session, error)

	// GetByAccessTokenHash retrieves a session by access token hash.
	GetByAccessTokenHash(ctx context.Context, hash string) (*Session, error)

	// GetActiveByUserID retrieves all active sessions for a user.
	GetActiveByUserID(ctx context.Context, userID shared.ID) ([]*Session, error)

	// Update updates an existing session.
	Update(ctx context.Context, session *Session) error

	// Delete deletes a session.
	Delete(ctx context.Context, id shared.ID) error

	// RevokeAllByUserID revokes all sessions for a user.
	RevokeAllByUserID(ctx context.Context, userID shared.ID) error

	// RevokeAllByUserIDExcept revokes all sessions for a user except the specified session.
	RevokeAllByUserIDExcept(ctx context.Context, userID shared.ID, exceptSessionID shared.ID) error

	// CountActiveByUserID counts active sessions for a user.
	CountActiveByUserID(ctx context.Context, userID shared.ID) (int, error)

	// GetOldestActiveByUserID retrieves the oldest active session for a user.
	// Returns nil if no active sessions exist.
	GetOldestActiveByUserID(ctx context.Context, userID shared.ID) (*Session, error)

	// DeleteExpired deletes all expired sessions (for cleanup job).
	DeleteExpired(ctx context.Context) (int64, error)
}

// RefreshTokenRepository defines the interface for refresh token persistence.
type RefreshTokenRepository interface {
	// Create creates a new refresh token.
	Create(ctx context.Context, token *RefreshToken) error

	// GetByID retrieves a refresh token by its ID.
	GetByID(ctx context.Context, id shared.ID) (*RefreshToken, error)

	// GetByTokenHash retrieves a refresh token by its hash.
	GetByTokenHash(ctx context.Context, hash string) (*RefreshToken, error)

	// GetByFamily retrieves all refresh tokens in a family.
	GetByFamily(ctx context.Context, family shared.ID) ([]*RefreshToken, error)

	// Update updates a refresh token.
	Update(ctx context.Context, token *RefreshToken) error

	// Delete deletes a refresh token.
	Delete(ctx context.Context, id shared.ID) error

	// RevokeByFamily revokes all tokens in a family (for replay attack detection).
	RevokeByFamily(ctx context.Context, family shared.ID) error

	// RevokeBySessionID revokes all tokens for a session.
	RevokeBySessionID(ctx context.Context, sessionID shared.ID) error

	// RevokeByUserID revokes all tokens for a user.
	RevokeByUserID(ctx context.Context, userID shared.ID) error

	// DeleteExpired deletes all expired tokens (for cleanup job).
	DeleteExpired(ctx context.Context) (int64, error)
}
