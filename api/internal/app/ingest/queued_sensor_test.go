package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The async worker re-reads the sensor of a queued job (RFC-040 §5.2): it
// used to rebuild the sensor as active from the job, so a report queued just
// before a revoke was still processed.

// tenantSensorRepo serves GetByTenantAndID; any other call panics.
type tenantSensorRepo struct {
	sensor.Repository
	rows map[shared.ID]*sensor.Sensor
	err  error
}

func (r *tenantSensorRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	if r.err != nil {
		return nil, r.err
	}
	if a, ok := r.rows[id]; ok && a.TenantID != nil && *a.TenantID == tenantID {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

type recordingAuditRepo struct {
	audit.Repository
	logs []*audit.AuditLog
}

func (r *recordingAuditRepo) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

func queuedService(rows ...*sensor.Sensor) (*Service, *recordingAuditRepo) {
	repo := &tenantSensorRepo{rows: map[shared.ID]*sensor.Sensor{}}
	for _, a := range rows {
		repo.rows[a.ID] = a
	}
	auditRepo := &recordingAuditRepo{}
	return &Service{logger: logger.NewNop(), sensorRepo: repo, auditRepo: auditRepo}, auditRepo
}

func TestJobProcessor_DropsWorkOfSensorsTakenOutOfService(t *testing.T) {
	tenantID, otherTenant := shared.NewID(), shared.NewID()
	mk := func(tid shared.ID, st sensor.SensorStatus) *sensor.Sensor {
		return &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: st}
	}
	revoked := mk(tenantID, sensor.SensorStatusRevoked)
	disabled := mk(tenantID, sensor.SensorStatusDisabled)
	foreign := mk(otherTenant, sensor.SensorStatusActive)
	deleted := shared.NewID()

	cases := map[string]struct {
		sensorID *shared.ID
		reason   string
	}{
		"revoked":              {&revoked.ID, "the sensor was revoked"},
		"disabled":             {&disabled.ID, "the sensor is disabled"},
		"deleted":              {&deleted, "the sensor no longer exists"},
		"other tenant's":       {&foreign.ID, "the sensor no longer exists"},
		"job without a sensor": {nil, "the job names no sensor"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, auditRepo := queuedService(revoked, disabled, foreign)
			ing := &stubIngester{out: &Output{}}
			p := &JobProcessor{service: ing, sensors: svc}

			out, err := p.Process(context.Background(),
				ingestjob.NewJob(tenantID, tc.sensorID, "scan-7", "trivy", []byte(`{"version":"1.0"}`)))
			if err != nil {
				t.Fatalf("a dropped job must complete, not be retried: %v", err)
			}
			if ing.called {
				t.Fatal("report of a sensor taken out of service was ingested")
			}
			var res DroppedJob
			if err := json.Unmarshal(out, &res); err != nil || !res.Dropped || res.Reason != tc.reason {
				t.Fatalf("result %s, want dropped with reason %q", out, tc.reason)
			}
			if len(auditRepo.logs) != 1 {
				t.Fatalf("%d audit entries, want 1", len(auditRepo.logs))
			}
			l := auditRepo.logs[0]
			if l.Action() != audit.ActionIngestFailed || l.Result() != audit.ResultDenied ||
				l.ResourceID() != "scan-7" || l.TenantID() == nil || *l.TenantID() != tenantID {
				t.Fatalf("audit entry %s/%s %s tenant %v", l.Action(), l.Result(), l.ResourceID(), l.TenantID())
			}
		})
	}
}

func TestJobProcessor_ActiveSensorIngestsAsTheStoredSensor(t *testing.T) {
	tenantID := shared.NewID()
	active := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, Status: sensor.SensorStatusActive,
		Reported: sensor.ReportOf("trivy")}
	svc, auditRepo := queuedService(active)
	var got *sensor.Sensor
	p := &JobProcessor{service: ingesterFunc(func(agt *sensor.Sensor) { got = agt }), sensors: svc}

	if _, err := p.Process(context.Background(),
		ingestjob.NewJob(tenantID, &active.ID, "scan-8", "trivy", []byte(`{"version":"1.0"}`))); err != nil {
		t.Fatal(err)
	}
	if got != active {
		t.Fatalf("ingested as %+v, want the stored sensor", got)
	}
	if len(auditRepo.logs) != 0 {
		t.Fatalf("%d audit entries for an accepted job, want 0", len(auditRepo.logs))
	}
}

func TestJobProcessor_SensorLookupFailureRetries(t *testing.T) {
	svc := &Service{logger: logger.NewNop(), sensorRepo: &tenantSensorRepo{err: errors.New("db down")}}
	ing := &stubIngester{out: &Output{}}
	sensorID := shared.NewID()
	p := &JobProcessor{service: ing, sensors: svc}
	if _, err := p.Process(context.Background(),
		ingestjob.NewJob(shared.NewID(), &sensorID, "scan-9", "trivy", []byte(`{"version":"1.0"}`))); err == nil {
		t.Fatal("lookup failure: job completed, want an error (retry)")
	}
	if ing.called {
		t.Fatal("report ingested without a sensor check")
	}

	// Not wired at all: fail closed.
	p = &JobProcessor{service: ing}
	if _, err := p.Process(context.Background(),
		ingestjob.NewJob(shared.NewID(), &sensorID, "scan-9", "trivy", []byte(`{"version":"1.0"}`))); err == nil || ing.called {
		t.Fatal("no sensor check wired: job processed, want an error")
	}
}

type ingesterFunc func(agt *sensor.Sensor)

func (f ingesterFunc) Ingest(_ context.Context, agt *sensor.Sensor, _ Input) (*Output, error) {
	f(agt)
	return &Output{}, nil
}
