package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
)

// CreateUserInput represents the input for creating a user.
type CreateUserInput struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=72"`
	Name     string `json:"name" validate:"required,min=1,max=255"`
}

// UpdateUserInput represents the input for updating a user.
type UpdateUserInput struct {
	ID       string  `json:"id" validate:"required,uuid"`
	Name     *string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Email    *string `json:"email,omitempty" validate:"omitempty,email,max=255"`
	Password *string `json:"password,omitempty" validate:"omitempty,min=8,max=72"`
	Status   *string `json:"status,omitempty" validate:"omitempty,user_status"`
}

// ListUsersFilter represents filters for listing users.
type ListUsersFilter struct {
	Search    string   `json:"search"`
	Status    []string `json:"status"`
	Page      int      `json:"page"`
	PerPage   int      `json:"per_page"`
	SortBy    string   `json:"sort_by"`
	SortOrder string   `json:"sort_order"`
}

// UserService defines the interface for user operations.
type UserService interface {
	// Create creates a new user.
	Create(ctx context.Context, input CreateUserInput) (*user.User, error)

	// Get retrieves a user by ID.
	Get(ctx context.Context, userID shared.ID) (*user.User, error)

	// GetByEmail retrieves a user by email.
	GetByEmail(ctx context.Context, email string) (*user.User, error)

	// List returns paginated users matching the filter.
	List(ctx context.Context, filter ListUsersFilter) (*ListResult[*user.User], error)

	// Update updates an existing user.
	Update(ctx context.Context, input UpdateUserInput) (*user.User, error)

	// Delete soft-deletes a user.
	Delete(ctx context.Context, userID shared.ID) error

	// Suspend suspends a user account.
	Suspend(ctx context.Context, userID shared.ID) error

	// Activate activates a suspended user account.
	Activate(ctx context.Context, userID shared.ID) error

	// ChangePassword changes user password.
	ChangePassword(ctx context.Context, userID shared.ID, oldPassword, newPassword string) error
}
