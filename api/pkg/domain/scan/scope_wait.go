package scan

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeWait is a scan saved to start once the pending scope entries that
// cover its targets are approved (RFC-054 §7).
type ScopeWait struct {
	ScanID      shared.ID
	TenantID    shared.ID
	RequestedBy *shared.ID
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// ScopeWaitRepository keeps the waits. Every call is tenant-scoped.
type ScopeWaitRepository interface {
	Create(ctx context.Context, w ScopeWait) error
	// ListByTenant returns the tenant's unexpired waits, oldest first, and
	// removes its expired ones.
	ListByTenant(ctx context.Context, tenantID shared.ID, limit int) ([]ScopeWait, error)
	// Exists reports whether the scan waits.
	Exists(ctx context.Context, tenantID, scanID shared.ID) (bool, error)
	// Claim deletes the wait; true only for the caller that deleted it.
	Claim(ctx context.Context, tenantID, scanID shared.ID) (bool, error)
}
