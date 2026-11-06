// Package scmapp holds the code-host app installations an organization binds
// to post CI checks and pull request comments
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).
package scmapp

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Providers.
const (
	ProviderGitHub = "github"
)

// Statuses. Only an active installation is used.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted"
)

// Errors.
var (
	ErrNotFound = fmt.Errorf("%w: SCM app installation not found", shared.ErrNotFound)
	// ErrBoundElsewhere: the installation is bound to another organization.
	// The message never names it.
	ErrBoundElsewhere = fmt.Errorf("%w: this installation is already bound to an organization", shared.ErrConflict)
	// ErrNotAuthorized: the person completing the install cannot access the
	// installation on the code host, or the install state is not theirs.
	ErrNotAuthorized = fmt.Errorf("%w: the installation could not be verified for you", shared.ErrForbidden)
)

// Installation is a code-host app installation bound to one tenant.
type Installation struct {
	ID                  shared.ID
	TenantID            shared.ID
	Provider            string
	InstallationID      int64
	AccountLogin        string
	AccountID           int64
	AccountType         string
	RepositorySelection string
	Status              string
	CreatedBy           *shared.ID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Active reports whether the installation may be used.
func (i *Installation) Active() bool { return i != nil && i.Status == StatusActive }

// Repository stores installations. Every read and write except
// GetByInstallationID and SetStatusByInstallationID (the code host's webhook,
// which names no tenant) is tenant-scoped.
type Repository interface {
	// Create binds an installation to a tenant; ErrBoundElsewhere when another
	// tenant holds it. Binding it again to the same tenant re-activates it.
	Create(ctx context.Context, inst *Installation) error
	List(ctx context.Context, tenantID shared.ID) ([]Installation, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*Installation, error)
	// ActiveForAccount returns the tenant's active installation on an account
	// (organization or user login), or ErrNotFound.
	ActiveForAccount(ctx context.Context, tenantID shared.ID, provider, accountLogin string) (*Installation, error)
	Delete(ctx context.Context, tenantID, id shared.ID) error
	GetByInstallationID(ctx context.Context, provider string, installationID int64) (*Installation, error)
	SetStatusByInstallationID(ctx context.Context, provider string, installationID int64, status string) (int64, error)
}
