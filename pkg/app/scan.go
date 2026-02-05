package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/scansession"
	"github.com/openctemio/api/pkg/domain/shared"
)

// CreateScanInput represents the input for creating a scan.
type CreateScanInput struct {
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	Name         string   `json:"name" validate:"required,min=1,max=255"`
	Description  string   `json:"description" validate:"max=1000"`
	ToolID       string   `json:"tool_id" validate:"required,uuid"`
	AssetGroupID string   `json:"asset_group_id" validate:"omitempty,uuid"`
	AssetIDs     []string `json:"asset_ids" validate:"omitempty,dive,uuid"`
	Schedule     string   `json:"schedule" validate:"omitempty,cron"`
	Parameters   map[string]any `json:"parameters"`
}

// UpdateScanInput represents the input for updating a scan.
type UpdateScanInput struct {
	TenantID    string          `json:"tenant_id" validate:"required,uuid"`
	ID          string          `json:"id" validate:"required,uuid"`
	Name        *string         `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string         `json:"description,omitempty" validate:"omitempty,max=1000"`
	Schedule    *string         `json:"schedule,omitempty" validate:"omitempty,cron"`
	Parameters  *map[string]any `json:"parameters,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
}

// ListScansFilter represents filters for listing scans.
type ListScansFilter struct {
	TenantID  string   `json:"tenant_id"`
	ToolIDs   []string `json:"tool_ids"`
	Status    []string `json:"status"`
	Search    string   `json:"search"`
	Page      int      `json:"page"`
	PerPage   int      `json:"per_page"`
	SortBy    string   `json:"sort_by"`
	SortOrder string   `json:"sort_order"`
}

// ScanService defines the interface for scan operations.
type ScanService interface {
	// Create creates a new scan configuration.
	Create(ctx context.Context, input CreateScanInput) (*scan.Scan, error)

	// Get retrieves a scan by ID within a tenant.
	Get(ctx context.Context, tenantID, scanID shared.ID) (*scan.Scan, error)

	// List returns paginated scans matching the filter.
	List(ctx context.Context, filter ListScansFilter) (*ListResult[*scan.Scan], error)

	// Update updates an existing scan.
	Update(ctx context.Context, input UpdateScanInput) (*scan.Scan, error)

	// Delete soft-deletes a scan.
	Delete(ctx context.Context, tenantID, scanID shared.ID) error

	// Trigger triggers a scan to run.
	Trigger(ctx context.Context, tenantID, scanID shared.ID) error

	// Cancel cancels a running scan.
	Cancel(ctx context.Context, tenantID, scanID shared.ID) error

	// Enable enables a scheduled scan.
	Enable(ctx context.Context, tenantID, scanID shared.ID) error

	// Disable disables a scheduled scan.
	Disable(ctx context.Context, tenantID, scanID shared.ID) error
}

// ScanSessionService defines the interface for scan session operations.
type ScanSessionService interface {
	// GetSession retrieves a specific scan session.
	GetSession(ctx context.Context, tenantID, sessionID shared.ID) (*scansession.ScanSession, error)

	// ListSessions returns scan sessions for a scan.
	ListSessions(ctx context.Context, tenantID, scanID shared.ID, page, perPage int) (*ListResult[*scansession.ScanSession], error)

	// GetLatestSession returns the latest session for a scan.
	GetLatestSession(ctx context.Context, tenantID, scanID shared.ID) (*scansession.ScanSession, error)
}
