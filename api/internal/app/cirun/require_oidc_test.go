package cirun

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSettings struct {
	require bool
	err     error
	reads   int
}

func (f *fakeSettings) CIRequireOIDC(context.Context, shared.ID) (bool, error) {
	f.reads++
	return f.require, f.err
}

func (f *fakeSettings) SetCIRequireOIDC(context.Context, shared.ID, bool) error { return nil }

type countingAudit struct{ n int }

func (c *countingAudit) LogEvent(context.Context, auditapp.AuditContext, auditapp.AuditEvent) error {
	c.n++
	return nil
}

func TestRunnerKeyPolicy(t *testing.T) {
	tid := shared.NewID()
	runner := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeRunner}
	standalone := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeWorker, ExecutionMode: sensor.ExecutionModeStandalone}
	daemon := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeWorker, ExecutionMode: sensor.ExecutionModeDaemon}
	platform := &sensor.Sensor{ID: shared.NewID(), Type: sensor.SensorTypeRunner}

	store := &fakeSettings{require: true}
	audit := &countingAudit{}
	p := NewRunnerKeyPolicy(store, audit, nil)
	now := time.Now()
	p.now = func() time.Time { return now }
	ctx := context.Background()

	if p.Refused(ctx, daemon, "", "") || p.Refused(ctx, platform, "", "") || store.reads != 0 {
		t.Fatalf("a daemon or tenant-less sensor was checked (%d reads)", store.reads)
	}
	if !p.Refused(ctx, runner, "", "") || !p.Refused(ctx, standalone, "", "") {
		t.Fatal("a CI sensor key passed while OIDC is required")
	}
	// One audit row per sensor per period.
	p.Refused(ctx, runner, "", "")
	if audit.n != 2 {
		t.Fatalf("audit rows = %d, want 2 (one per sensor)", audit.n)
	}
	now = now.Add(runnerKeyAuditEvery)
	p.Refused(ctx, runner, "", "")
	if audit.n != 3 {
		t.Fatalf("audit rows after the period = %d, want 3", audit.n)
	}
	store.require = false
	if p.Refused(ctx, runner, "", "") {
		t.Fatal("refused although the organization allows sensor keys for CI")
	}
	// An unreadable setting refuses (fail closed).
	store.err = errors.New("db down")
	if !p.Refused(ctx, runner, "", "") {
		t.Fatal("an unreadable setting let a CI sensor key through")
	}
}
