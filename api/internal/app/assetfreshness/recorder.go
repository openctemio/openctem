// Package assetfreshness records when each enrichable attribute class of an
// asset was last observed and serves the asset's freshness
// (docs/architecture/asset-freshness.md).
package assetfreshness

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Recorder turns the assets an ingest wrote into class observations.
type Recorder struct {
	repo   freshdom.Repository
	logger *logger.Logger
}

// NewRecorder creates the recorder.
func NewRecorder(repo freshdom.Repository, log *logger.Logger) *Recorder {
	return &Recorder{repo: repo, logger: log.With("component", "asset-freshness")}
}

// Observations maps the assets a report of the tool wrote to the classes it
// observed on them. Pure; exported for tests.
func Observations(tool string, observedAt time.Time, assets []*assetdom.Asset) []freshdom.Observation {
	var out []freshdom.Observation
	for _, a := range assets {
		if a == nil {
			continue
		}
		for _, c := range freshdom.ClassesForTool(tool, a.Type()) {
			out = append(out, freshdom.Observation{AssetID: a.ID(), Class: c, ObservedAt: observedAt, Source: tool})
		}
	}
	return out
}

// AssetsObserved records the observations of one ingest batch. It matches
// ingest.AssetsObservedCallback. A failure is logged and counted; it never
// fails the ingest.
func (r *Recorder) AssetsObserved(ctx context.Context, tenantID shared.ID, tool string, observedAt time.Time, assets []*assetdom.Asset) {
	if r == nil || r.repo == nil {
		return
	}
	obs := Observations(tool, observedAt, assets)
	if len(obs) == 0 {
		return
	}
	if err := r.repo.Record(ctx, tenantID, obs); err != nil {
		metrics.AssetFreshnessRecordErrorsTotal.Inc()
		r.logger.Warn("asset freshness not recorded", "tenant_id", tenantID.String(), "tool", tool,
			"observations", len(obs), "error", logger.SanitizeError(err))
		return
	}
	for _, o := range obs {
		metrics.AssetFreshnessObservationsTotal.WithLabelValues(string(o.Class)).Inc()
	}
}
