package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
)

// LoginInput represents the input for user login.
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// RegisterInput represents the input for user registration.
type RegisterInput struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=72"`
	Name     string `json:"name" validate:"required,min=1,max=255"`
}

// AuthResult represents the result of authentication.
type AuthResult struct {
	User         *user.User `json:"user"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	ExpiresAt    int64      `json:"expires_at"`
}

// RefreshTokenInput represents the input for token refresh.
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// AuthService defines the interface for authentication operations.
type AuthService interface {
	// Login authenticates a user with email and password.
	Login(ctx context.Context, input LoginInput) (*AuthResult, error)

	// Register creates a new user account.
	Register(ctx context.Context, input RegisterInput) (*AuthResult, error)

	// RefreshToken refreshes an access token using a refresh token.
	RefreshToken(ctx context.Context, input RefreshTokenInput) (*AuthResult, error)

	// Logout invalidates a user's session.
	Logout(ctx context.Context, sessionID shared.ID) error

	// LogoutAll invalidates all sessions for a user.
	LogoutAll(ctx context.Context, userID shared.ID) error

	// VerifyToken verifies an access token and returns the user.
	VerifyToken(ctx context.Context, token string) (*user.User, error)
}

// SessionService defines the interface for session management.
type SessionService interface {
	// Create creates a new session.
	Create(ctx context.Context, userID, tenantID shared.ID, metadata map[string]string) (*session.Session, error)

	// Get retrieves a session by ID.
	Get(ctx context.Context, sessionID shared.ID) (*session.Session, error)

	// GetByUserID returns all sessions for a user.
	GetByUserID(ctx context.Context, userID shared.ID) ([]*session.Session, error)

	// Revoke revokes a session.
	Revoke(ctx context.Context, sessionID shared.ID) error

	// RevokeAll revokes all sessions for a user.
	RevokeAll(ctx context.Context, userID shared.ID) error

	// Touch updates the last activity timestamp.
	Touch(ctx context.Context, sessionID shared.ID) error

	// CleanupExpired removes expired sessions.
	CleanupExpired(ctx context.Context) (int64, error)
}
