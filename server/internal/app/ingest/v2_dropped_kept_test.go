package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type droppingSensors struct{ reason string }

func (d droppingSensors) QueuedWorkSensor(_ context.Context, _ shared.ID, _, _ *shared.ID, _ *int, reportID string) (*sensor.Sensor, *DroppedJob, error) {
	return nil, &DroppedJob{ReportID: reportID, Dropped: true, Reason: d.reason}, nil
}

type failingReports struct {
	ingestreport.Repository
	rep    *ingestreport.Report
	failed int
}

func (r *failingReports) GetByID(context.Context, shared.ID) (*ingestreport.Report, error) {
	return r.rep, nil
}

func (r *failingReports) MarkFailed(context.Context, shared.ID) error {
	r.failed++
	return nil
}

// A report the worker's re-check refuses to apply (sensor revoked, command
// taken back) is never completed: a completed job empties its payload, and
// the sensor may have deleted its own copy on the 202 (research/467 D0).
// The job fails for good with the report_dropped code, which keeps the
// sealed segment for the staging retention, and the report shows failed.
func TestV2Process_DroppedReportKeepsItsPayload(t *testing.T) {
	tenant := shared.NewID()
	rep := &ingestreport.Report{ID: shared.NewID(), TenantID: tenant, ReportID: "r-1", State: protov2.StateQueued}
	reports := &failingReports{rep: rep}
	seq := 0
	job := ingestjob.NewV2Job(tenant, nil, "r-1", ingestjob.V2Segment{ReportRef: rep.ID, Seq: &seq}, []byte("sealed"))
	p := &V2JobProcessor{service: &Service{}, sensors: droppingSensors{reason: reasonRunTakenBack},
		reports: reports, logger: logger.NewNop()}

	out, err := p.Process(context.Background(), job)
	var perm *ingestjob.PermanentError
	if !errors.As(err, &perm) || perm.Code != ErrorReportDropped {
		t.Fatalf("Process = %s, %v; want a permanent %s failure (dead job, payload kept)", out, err, ErrorReportDropped)
	}
	if out != nil {
		t.Fatalf("a dropped report produced a completion result %s: its payload would be emptied", out)
	}
	if reports.failed != 1 {
		t.Fatalf("report marked failed %d times, want 1", reports.failed)
	}
}
