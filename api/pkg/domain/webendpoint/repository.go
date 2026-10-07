package webendpoint

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

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
}

// Repository stores the sub-inventory. Every method is tenant-scoped: an id
// of another tenant behaves as an id that does not exist.
type Repository interface {
	// Record upserts the observations of one origin asset of the tenant in
	// one transaction. The caller has checked that the origin is a live
	// asset of the tenant the report may write to; Record re-checks the
	// tenant through the composite foreign key.
	Record(ctx context.Context, tenantID, originAssetID shared.ID, obs []Observation, prov Provenance) (RecordResult, error)
}
