package scanfreeze

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Filter narrows a list of a tenant's windows.
type Filter struct {
	// ScanZoneID lists the windows of one zone.
	ScanZoneID *shared.ID
	// TenantWide lists only the windows that freeze the whole tenant.
	TenantWide bool
}

// Repository stores freeze windows. Every method is tenant-scoped; a window
// of another tenant is ErrNotFound.
type Repository interface {
	Create(ctx context.Context, w *Window) error
	// GetByID returns the window with ActiveUntil set when it is active now.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Window, error)
	// List returns the tenant's windows, each with ActiveUntil set when it
	// is active now.
	List(ctx context.Context, tenantID shared.ID, f Filter) ([]*Window, error)
	Update(ctx context.Context, w *Window) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	Count(ctx context.Context, tenantID shared.ID) (int, error)
	// ActiveAt returns the enabled windows active at at that apply to work
	// in any of zoneIDs or outside every zone: the tenant-wide windows and
	// the windows of those zones. ActiveUntil is set on each.
	ActiveAt(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, at time.Time) ([]*Window, error)
}

// Latest returns the window of ws that stays active the longest, or nil.
func Latest(ws []*Window) *Window {
	var out *Window
	for _, w := range ws {
		if w.ActiveUntil == nil {
			continue
		}
		if out == nil || w.ActiveUntil.After(*out.ActiveUntil) {
			out = w
		}
	}
	return out
}
