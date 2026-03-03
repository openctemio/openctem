package module

import (
	"context"
)

// ModuleRepository defines the interface for module persistence operations.
type ModuleRepository interface {
	// GetByID retrieves a module by its ID.
	GetByID(ctx context.Context, id string) (*Module, error)

	// GetBySlug retrieves a module by its slug.
	GetBySlug(ctx context.Context, slug string) (*Module, error)

	// ListAll returns all modules.
	ListAll(ctx context.Context) ([]*Module, error)

	// ListActive returns all active modules.
	ListActive(ctx context.Context) ([]*Module, error)

	// ListByCategory returns modules filtered by category.
	ListByCategory(ctx context.Context, category string) ([]*Module, error)
}
