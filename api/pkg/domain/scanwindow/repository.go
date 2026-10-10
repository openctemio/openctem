package scanwindow

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Filter narrows a list of a tenant's policies.
type Filter struct {
	// EnabledOnly lists only enabled policies.
	EnabledOnly bool
}

// Repository stores policies. Every method is tenant-scoped; a policy of
// another tenant is ErrNotFound.
type Repository interface {
	Create(ctx context.Context, p *Policy) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Policy, error)
	// List returns the tenant's policies ordered by name.
	List(ctx context.Context, tenantID shared.ID, f Filter) ([]*Policy, error)
	Update(ctx context.Context, p *Policy) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	Count(ctx context.Context, tenantID shared.ID) (int, error)
}

// OverrideRepository stores overrides. Every method is tenant-scoped.
type OverrideRepository interface {
	Create(ctx context.Context, o *Override) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Override, error)
	// ListActive returns the overrides active at t.
	ListActive(ctx context.Context, tenantID shared.ID, t time.Time) ([]*Override, error)
	// ListRecent returns the most recent overrides (active or not), newest
	// first, at most limit.
	ListRecent(ctx context.Context, tenantID shared.ID, limit int) ([]*Override, error)
	// Revoke ends an active override; ErrOverrideNotFound when there is
	// none of the tenant with that id still active.
	Revoke(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error
}

// Hold is why a pending job waits for a window (commands.window_hold).
type Hold struct {
	// Reason: "window" (outside its windows), "concurrency" (a cap is
	// reached), "closed" (a window closed under the running job).
	Reason     string     `json:"reason"`
	NextOpenAt *time.Time `json:"next_open_at,omitempty"`
	Never      bool       `json:"never,omitempty"`
	Blocking   []Block    `json:"blocking,omitempty"`
	CheckedAt  time.Time  `json:"checked_at"`
}

// Hold reasons.
const (
	HoldWindow      = "window"
	HoldConcurrency = "concurrency"
	HoldClosed      = "closed"
)

// TargetAsset is an asset a target names, with what a selector matches on.
type TargetAsset struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Criticality     string   `json:"criticality"`
	Tags            []string `json:"tags"`
	GroupIDs        []string `json:"group_ids"`
	BusinessUnitIDs []string `json:"business_unit_ids"`
}

// AssetMatcher finds the tenant's assets behind targets: an asset named as
// the target or its host, and for a CIDR target the IP assets inside it.
type AssetMatcher interface {
	MatchTargetAssets(ctx context.Context, tenantID shared.ID, targets []string) (map[string][]TargetAsset, error)
}
