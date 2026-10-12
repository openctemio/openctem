package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type stubIngester struct {
	gotTenant shared.ID
	gotReport *ctis.Report
	out       *Output
	err       error
	called    bool
}

func (s *stubIngester) Ingest(_ context.Context, agt *sensor.Sensor, input Input) (*Output, error) {
	if agt.TenantID != nil {
		s.gotTenant = *agt.TenantID
	}
	s.gotReport = input.Report
	s.called = true
	return s.out, s.err
}

// activeSensors answers every lookup with an active sensor of the tenant.
type activeSensors struct{}

func (activeSensors) QueuedWorkSensor(_ context.Context, tenantID shared.ID, sensorID *shared.ID, _ string) (*sensor.Sensor, *DroppedJob, error) {
	return &sensor.Sensor{ID: *sensorID, TenantID: &tenantID, Status: sensor.SensorStatusActive}, nil, nil
}

func TestParseReport_FlatAndWrapped(t *testing.T) {
	flat := []byte(`{"version":"1.0"}`)
	if r, err := ParseReport(flat); err != nil || r.Version != "1.0" {
		t.Fatalf("flat parse: r=%v err=%v", r, err)
	}
	wrapped := []byte(`{"report":{"version":"1.0"}}`)
	if r, err := ParseReport(wrapped); err != nil || r.Version != "1.0" {
		t.Fatalf("wrapped parse: r=%v err=%v", r, err)
	}
	if _, err := ParseReport([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestJobProcessor_Process_IngestsAndReturnsCounts(t *testing.T) {
	tenantID := shared.NewID()
	sensorID := shared.NewID()
	ing := &stubIngester{out: &Output{
		ReportID:        "scan-9",
		AssetsCreated:   2,
		FindingsCreated: 7,
		FindingsUpdated: 3,
	}}
	p := &JobProcessor{service: ing, sensors: activeSensors{}}

	job := ingestjob.NewJob(tenantID, &sensorID, "scan-9", "trivy", []byte(`{"version":"1.0"}`))
	out, err := p.Process(context.Background(), job)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	if ing.gotTenant != tenantID {
		t.Fatalf("ingest got tenant %s, want %s", ing.gotTenant, tenantID)
	}
	if ing.gotReport == nil || ing.gotReport.Version != "1.0" {
		t.Fatalf("ingest got wrong report: %+v", ing.gotReport)
	}

	var res JobResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if res.FindingsCreated != 7 || res.AssetsCreated != 2 || res.ReportID != "scan-9" {
		t.Fatalf("unexpected counts: %+v", res)
	}
}

func TestJobProcessor_Process_ParseError(t *testing.T) {
	p := &JobProcessor{service: &stubIngester{}, sensors: activeSensors{}}
	job := ingestjob.NewJob(shared.NewID(), nil, "scan-1", "trivy", []byte(`garbage`))
	if _, err := p.Process(context.Background(), job); err == nil {
		t.Fatal("expected parse error to propagate")
	}
}

func TestJobProcessor_Process_IngestError(t *testing.T) {
	sensorID := shared.NewID()
	p := &JobProcessor{service: &stubIngester{err: errors.New("db down")}, sensors: activeSensors{}}
	job := ingestjob.NewJob(shared.NewID(), &sensorID, "scan-1", "trivy", []byte(`{"version":"1.0"}`))
	if _, err := p.Process(context.Background(), job); err == nil {
		t.Fatal("expected ingest error to propagate")
	}
}
