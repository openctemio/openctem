package session

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for session operations.
var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session has expired")
	ErrSessionRevoked       = errors.New("session has been revoked")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
	ErrRefreshTokenUsed     = errors.New("refresh token has already been used")
	ErrRefreshTokenRevoked  = errors.New("refresh token has been revoked")
	ErrTokenFamilyMismatch  = errors.New("refresh token family mismatch (possible replay attack)")
	ErrMaxSessionsReached   = errors.New("maximum number of active sessions reached")
	ErrInvalidToken         = errors.New("invalid token")
)

// SessionNotFoundError returns a session not found error with ID.
func SessionNotFoundError(id shared.ID) error {
	return fmt.Errorf("%w: %s", ErrSessionNotFound, id.String())
}

// RefreshTokenNotFoundError returns a refresh token not found error.
func RefreshTokenNotFoundError(id shared.ID) error {
	return fmt.Errorf("%w: %s", ErrRefreshTokenNotFound, id.String())
}
