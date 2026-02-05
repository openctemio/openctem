package scanprofile

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing scan profiles.
type Filter struct {
	TenantID  *shared.ID
	IsDefault *bool
	IsSystem  *bool
	Tags      []string
	Search    string
}

// Repository defines the interface for scan profile persistence.
type Repository interface {
	// Create creates a new scan profile.
	Create(ctx context.Context, profile *ScanProfile) error

	// GetByID retrieves a scan profile by ID.
	GetByID(ctx context.Context, id shared.ID) (*ScanProfile, error)

	// GetByTenantAndID retrieves a scan profile by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*ScanProfile, error)

	// GetByTenantAndName retrieves a scan profile by tenant and name.
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*ScanProfile, error)

	// GetDefaultByTenant retrieves the default scan profile for a tenant.
	GetDefaultByTenant(ctx context.Context, tenantID shared.ID) (*ScanProfile, error)

	// List lists scan profiles with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*ScanProfile], error)

	// ListWithSystemProfiles lists tenant profiles AND system profiles.
	// Returns both tenant-specific profiles and system profiles (marked with is_system=true).
	ListWithSystemProfiles(ctx context.Context, tenantID shared.ID, filter Filter, page pagination.Pagination) (pagination.Result[*ScanProfile], error)

	// GetByIDWithSystemFallback retrieves a profile by ID, checking both tenant and system profiles.
	// This allows tenants to reference system profiles for use in scans.
	GetByIDWithSystemFallback(ctx context.Context, tenantID, id shared.ID) (*ScanProfile, error)

	// Update updates a scan profile.
	Update(ctx context.Context, profile *ScanProfile) error

	// Delete deletes a scan profile.
	Delete(ctx context.Context, id shared.ID) error

	// ClearDefaultForTenant clears the default flag for all profiles in a tenant.
	ClearDefaultForTenant(ctx context.Context, tenantID shared.ID) error

	// CountByTenant counts the number of profiles for a tenant.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error)
}
