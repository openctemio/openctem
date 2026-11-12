// Package assetresolution is the resolution state of an asset's host name:
// whether it resolves in DNS, when it last did and how many checks in a row
// failed (docs/architecture/scan-targets.md, "Names that do not resolve").
//
// The state is a fact about the name, not an ownership or scope decision:
// it only decides whether an ACTIVE stage takes the name. Passive stages
// keep taking it, so a name that resolves again comes back by itself.
package assetresolution

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// State is whether a name resolves.
type State string

// States. An asset without a row has an unknown state.
const (
	StateResolving    State = "resolving"
	StateNotResolving State = "not_resolving"
)

// Sources of an observation.
const (
	SourceResolveStage  = "resolve_stage"
	SourceSensorRefusal = "sensor_refusal"
	SourceObservation   = "observation"
)

// NotResolvingAfter is how many failed checks in a row make a name
// not_resolving: one failed lookup can be a resolver hiccup.
const NotResolvingAfter = 2

// Resolution is one asset's state.
type Resolution struct {
	AssetID    shared.ID  `json:"asset_id"`
	State      State      `json:"state"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	CheckedAt  time.Time  `json:"checked_at"`
	Failures   int        `json:"failures"`
	Source     string     `json:"source,omitempty"`
}

// Store keeps the states. Every call is tenant-scoped: an asset id or a name
// of another tenant reads and writes nothing.
type Store interface {
	// RecordResolved marks the assets resolving (failures back to 0).
	RecordResolved(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, at time.Time) error
	// RecordFailed counts one failed check for the assets; at
	// NotResolvingAfter in a row they become not_resolving.
	RecordFailed(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, at time.Time, source string) error
	// RecordFailedNames is RecordFailed for the tenant's assets with these
	// (lower-case) names.
	RecordFailedNames(ctx context.Context, tenantID shared.ID, names []string, at time.Time, source string) error
	// NotResolving returns which of the (lower-case) names belong to a
	// tenant asset in the not_resolving state.
	NotResolving(ctx context.Context, tenantID shared.ID, names []string) (map[string]bool, error)
	// Get returns the asset's state, nil when unknown.
	Get(ctx context.Context, tenantID, assetID shared.ID) (*Resolution, error)
}
