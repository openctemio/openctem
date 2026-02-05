package branch

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter defines criteria for filtering branches.
type Filter struct {
	RepositoryID *shared.ID // Repository ID (asset_repositories.asset_id)
	Name         string
	Types        []Type
	IsDefault    *bool
	ScanStatus   *ScanStatus
}

// ListOptions defines sorting options.
type ListOptions struct {
	SortBy    string // name, created_at, last_scanned_at
	SortOrder string // asc, desc
}

// Repository defines the branch repository interface.
type Repository interface {
	// Create persists a new branch.
	Create(ctx context.Context, branch *Branch) error

	// GetByID retrieves a branch by ID.
	GetByID(ctx context.Context, id shared.ID) (*Branch, error)

	// GetByName retrieves a branch by repository ID and name.
	GetByName(ctx context.Context, repositoryID shared.ID, name string) (*Branch, error)

	// Update updates an existing branch.
	Update(ctx context.Context, branch *Branch) error

	// Delete removes a branch.
	Delete(ctx context.Context, id shared.ID) error

	// List returns branches matching the filter.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*Branch], error)

	// ListByRepository returns all branches for a repository.
	ListByRepository(ctx context.Context, repositoryID shared.ID) ([]*Branch, error)

	// GetDefaultBranch returns the default branch for a repository.
	GetDefaultBranch(ctx context.Context, repositoryID shared.ID) (*Branch, error)

	// SetDefaultBranch sets a branch as the default for a repository.
	SetDefaultBranch(ctx context.Context, repositoryID shared.ID, branchID shared.ID) error

	// Count returns the number of branches matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// ExistsByName checks if a branch exists by repository ID and name.
	ExistsByName(ctx context.Context, repositoryID shared.ID, name string) (bool, error)
}
