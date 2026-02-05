package user

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for user operations.
var (
	ErrUserNotFound      = fmt.Errorf("user %w", shared.ErrNotFound)
	ErrUserAlreadyExists = fmt.Errorf("user %w", shared.ErrAlreadyExists)
	ErrUserSuspended     = errors.New("user is suspended")
	ErrUserInactive      = errors.New("user is inactive")
	ErrInvalidEmail      = fmt.Errorf("%w: invalid email", shared.ErrValidation)

	// Authentication errors
	ErrInvalidCredentials        = errors.New("invalid email or password")
	ErrAccountLocked             = errors.New("account is locked due to too many failed attempts")
	ErrEmailNotVerified          = errors.New("email address not verified")
	ErrPasswordTooWeak           = errors.New("password does not meet requirements")
	ErrInvalidVerificationToken  = errors.New("invalid or expired verification token")
	ErrInvalidPasswordResetToken = errors.New("invalid or expired password reset token")
	ErrCannotChangeOIDCPassword  = errors.New("cannot change password for OIDC users")
)

// NotFoundError creates a not found error for a specific user.
func NotFoundError(userID shared.ID) error {
	return fmt.Errorf("user with id %s %w", userID, shared.ErrNotFound)
}

// NotFoundByEmailError creates a not found error for a specific email.
func NotFoundByEmailError(email string) error {
	return fmt.Errorf("user with email %s %w", email, shared.ErrNotFound)
}

// NotFoundByKeycloakIDError creates a not found error for a specific Keycloak ID.
func NotFoundByKeycloakIDError(keycloakID string) error {
	return fmt.Errorf("user with keycloak_id %s %w", keycloakID, shared.ErrNotFound)
}

// AlreadyExistsError creates an already exists error for a specific email.
func AlreadyExistsError(email string) error {
	return fmt.Errorf("user with email %s %w", email, shared.ErrAlreadyExists)
}
