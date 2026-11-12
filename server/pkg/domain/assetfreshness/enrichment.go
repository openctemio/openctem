package assetfreshness

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Reason is why an asset is to be enriched.
type Reason string

// Reasons; the database CHECK holds the same values.
const (
	ReasonNewAsset Reason = "new_asset"
	ReasonStale    Reason = "stale"
	ReasonChange   Reason = "change"
	ReasonManual   Reason = "manual"
)

// Outcome is what the controller did with a claimed request.
type Outcome string

// Outcomes; the database CHECK holds the same values.
const (
	OutcomeClaimed    Outcome = "claimed"
	OutcomeDispatched Outcome = "dispatched"
	OutcomeDisabled   Outcome = "disabled"
	OutcomeNoProfile  Outcome = "no_profile"
	OutcomeRefused    Outcome = "refused"
	OutcomeFailed     Outcome = "failed"
)

// Profile is a built-in passive enrichment profile: a system workflow
// (migration asset_enrichment_profiles) for the asset types it enriches.
type Profile struct {
	Key        string
	WorkflowID shared.ID
	Types      []asset.AssetType
}

var profiles = []Profile{
	{"root_domains", shared.MustIDFromString("a0000003-0000-0000-0000-000000000001"), []asset.AssetType{asset.AssetTypeDomain}},
	{"host_names", shared.MustIDFromString("a0000003-0000-0000-0000-000000000002"), []asset.AssetType{asset.AssetTypeSubdomain}},
	{"addresses", shared.MustIDFromString("a0000003-0000-0000-0000-000000000003"), []asset.AssetType{asset.AssetTypeIPAddress}},
}

// Profiles returns the built-in profiles.
func Profiles() []Profile {
	out := make([]Profile, len(profiles))
	copy(out, profiles)
	return out
}

// ProfileFor returns the profile that enriches an asset type.
func ProfileFor(t asset.AssetType) (Profile, bool) {
	for _, p := range profiles {
		for _, pt := range p.Types {
			if pt == t {
				return p, true
			}
		}
	}
	return Profile{}, false
}

// Request is an asset's pending or last enrichment.
type Request struct {
	Reason       Reason     `json:"reason"`
	RequestedAt  time.Time  `json:"requested_at"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	Outcome      Outcome    `json:"outcome,omitempty"`
	LastRunID    *shared.ID `json:"last_run_id,omitempty"`
}

// Pending reports whether the request waits for the controller.
func (r Request) Pending() bool { return r.DispatchedAt == nil }

// RequestRepository stores enrichment requests. Every method is scoped to
// one tenant, except TenantsDue, which only lists tenant ids.
type RequestRepository interface {
	// Request upserts a request per asset of the tenant (ids of other
	// tenants match nothing). A pending request stays as it is; a request
	// dispatched within cooldown is not re-opened unless the reason is
	// manual. Returns how many requests were opened.
	Request(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason Reason, cooldown time.Duration) (int, error)
	// TenantsDue lists tenants whose oldest pending request is older than
	// debounce, or that have at least burst pending requests.
	TenantsDue(ctx context.Context, debounce time.Duration, burst int) ([]shared.ID, error)
	// DispatchedSince counts the tenant's requests dispatched to a run since t.
	DispatchedSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// Claim marks up to limit pending requests of the tenant as claimed,
	// oldest first, skipping rows another claimer holds.
	Claim(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error)
	// Settle records what happened to claimed requests.
	Settle(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, outcome Outcome, runID *shared.ID) error
	// Get returns the asset's request, nil when there is none.
	Get(ctx context.Context, tenantID, assetID shared.ID) (*Request, error)
}
