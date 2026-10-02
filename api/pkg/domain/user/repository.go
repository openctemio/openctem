package user

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Filter represents criteria for filtering users.
type Filter struct {
	Email    *string
	Status   *Status
	Statuses []Status
}

// WithEmail sets the email filter.
func (f Filter) WithEmail(email string) Filter {
	f.Email = &email
	return f
}

// WithStatus sets a single status filter.
func (f Filter) WithStatus(status Status) Filter {
	f.Status = &status
	return f
}

// WithStatuses sets multiple status filters.
func (f Filter) WithStatuses(statuses ...Status) Filter {
	f.Statuses = statuses
	return f
}

// Repository defines the interface for user persistence.
type Repository interface {
	// CRUD operations
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id shared.ID) (*User, error)
	GetByKeycloakID(ctx context.Context, keycloakID string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id shared.ID) error

	// Existence checks
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByKeycloakID(ctx context.Context, keycloakID string) (bool, error)

	// Upsert for Keycloak sync - creates or updates user, returns the user
	UpsertFromKeycloak(ctx context.Context, keycloakID, email, name string) (*User, error)

	// Batch operations
	GetByIDs(ctx context.Context, ids []shared.ID) ([]*User, error)

	// Count
	Count(ctx context.Context, filter Filter) (int64, error)

	// Local auth operations
	// GetByEmailForAuth retrieves a local user by email for authentication.
	GetByEmailForAuth(ctx context.Context, email string) (*User, error)

	// GetByEmailVerificationToken retrieves a user by email verification token.
	GetByEmailVerificationToken(ctx context.Context, token string) (*User, error)

	// GetByPasswordResetToken retrieves a user by password reset token.
	GetByPasswordResetToken(ctx context.Context, token string) (*User, error)
}
