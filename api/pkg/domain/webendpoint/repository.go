package webendpoint

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Stats are the counts of one filtered set of endpoints.
type Stats struct {
	Total       int64            `json:"total"`
	ByMethod    map[string]int64 `json:"by_method"`
	ByKind      map[string]int64 `json:"by_kind"`
	ByAuthState map[string]int64 `json:"by_auth_state"`
	ByState     map[string]int64 `json:"by_state"`
	// ExcludedUntested counts endpoints under a scope exclusion: recorded,
	// never tested (a coverage gap, not a clean bill of health).
	ExcludedUntested int64 `json:"excluded_untested"`
	// ExcludedSensitive counts excluded-untested endpoints on the
	// sensitive-path catalog; UnauthSensitive counts sensitive endpoints
	// answering 2xx without authentication.
	ExcludedSensitive int64 `json:"excluded_sensitive"`
	UnauthSensitive   int64 `json:"unauth_sensitive"`
}

// Update is a person's change to an endpoint: nil fields stay.
type Update struct {
	State  *State
	Labels *[]string
}

// Reader is the read side of the sub-inventory. List and stats take a
// filter compiled for the caller (tenant and data scope included); by-id
// reads are tenant-scoped, and the caller checks the origin's data scope.
type Reader interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Endpoint], error)
	StatsWhere(ctx context.Context, w *filterspec.Where) (*Stats, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*Endpoint, error)
	Params(ctx context.Context, tenantID, endpointID shared.ID) ([]Param, error)
	Update(ctx context.Context, tenantID, id shared.ID, u Update) error
}

// Provenance is where one ingest's observations came from. It is taken from
// the server-side binding of the report (the command the sensor was given,
// the authenticated sensor), never from the report body.
type Provenance struct {
	SensorID *shared.ID
	RunID    *shared.ID
	Tool     string
}

// RecordResult counts what one Record call did.
type RecordResult struct {
	Created int
	Updated int
	// OverCap counts new templates refused because their origin already
	// holds MaxActivePerOrigin active endpoints (or MaxScriptsPerOrigin
	// scripts).
	OverCap int
	// ParamsOverCap counts new parameters refused because their endpoint
	// already holds MaxParamsPerEndpoint.
	ParamsOverCap int
	// Events counts the change feed rows written.
	Events int
}

// Change feed event kinds.
const (
	EventAppeared      = "appeared"
	EventReturned      = "returned"
	EventGone          = "gone"
	EventStatusChanged = "status_changed"
	EventAuthChanged   = "auth_changed"
	EventParamAdded    = "param_added"
)

// Repository stores the sub-inventory. Every method is tenant-scoped: an id
// of another tenant behaves as an id that does not exist.
type Repository interface {
	// Record upserts the observations of one origin asset of the tenant in
	// one transaction. The caller has checked that the origin is a live
	// asset of the tenant the report may write to; Record re-checks the
	// tenant through the composite foreign key.
	Record(ctx context.Context, tenantID, originAssetID shared.ID, obs []Observation, prov Provenance) (RecordResult, error)
}
