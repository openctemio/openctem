package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProducerCIRun names the producer of a CI run's report in the ingest path
// (logs and the ingest audit): a CI run, never a sensor.
const ProducerCIRun = "ci-run"

// ciRunSubmitter is the submitter the ingest pipeline is handed for a CI
// run's report. A CI run is not a sensor and has no sensor row: the value
// carries only the tenant and a producer name, with a zero id and no sensor
// type, so findings carry no sensor id, no sensor's totals change, no
// sensor-role rule applies and no output contract is looked up. The ci_run
// binding decides what the report may change.
func ciRunSubmitter(tenantID, runID shared.ID) *sensor.Sensor {
	tid := tenantID
	return &sensor.Sensor{
		TenantID: &tid,
		Name:     ProducerCIRun + " " + runID.String(),
		Status:   sensor.SensorStatusActive,
	}
}

// IngestForCIRun applies a report a CI run uploaded with its run token
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md). The binding limits the
// report to the run's repository; the caller has already checked that every
// asset in the report is that repository.
func (s *Service) IngestForCIRun(ctx context.Context, tenantID, runID shared.ID, repository string, report *ctis.Report) (*Output, error) {
	return s.Ingest(ctx, ciRunSubmitter(tenantID, runID), Input{
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
