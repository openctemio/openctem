package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IngestForCIRun applies a report a CI run uploaded with its run token
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md). A CI run is not a
// sensor: there is no sensor row, so the report is submitted under a
// synthetic runner identity with a zero id (findings carry no sensor id and
// no sensor's totals change). The binding limits the report to the run's
// repository; the caller has already checked that every asset in the report
// is that repository.
func (s *Service) IngestForCIRun(ctx context.Context, tenantID, runID shared.ID, repository string, report *ctis.Report) (*Output, error) {
	tid := tenantID
	runner := &sensor.Sensor{
		TenantID: &tid,
		Name:     "ci-run " + runID.String(),
		Type:     sensor.SensorTypeRunner,
		Status:   sensor.SensorStatusActive,
	}
	return s.Ingest(ctx, runner, Input{
		Report: report,
		Options: Options{
			Binding:                 CIRunBinding(runID, repository),
			Route:                   "ci",
			RequireAssetForFindings: true,
			NoCatalogWrites:         true,
			DeferSensorStats:        true,
		},
	})
}
