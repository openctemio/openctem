package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestSensorLocalPolicy_StoredAndRead: a heartbeat's local policy report
// (RFC-040 §5.7) is stored with its time, read back by every read path, kept
// by a heartbeat without one, and the manifest path writes it on its own
// only for an active sensor of the tenant.
func TestSensorLocalPolicy_StoredAndRead(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := &SensorRepository{db: &DB{DB: db}}
	tenantID := seedTestTenant(ctx, t, db)
	id := seedSensor(ctx, t, db, tenantID, "online", nil, "nuclei", 0)

	a, err := repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil || a.LocalPolicy != nil || a.LocalPolicyReportedAt != nil {
		t.Fatalf("new sensor: %+v %v err %v", a.LocalPolicy, a.LocalPolicyReportedAt, err)
	}

	digest := "sha256:" + strings.Repeat("ab", 32)
	rep := &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced, Source: "file", Digest: digest,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: 2, Ports: "443", Tools: []string{"nuclei"}}}
	if ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, LocalPolicy: rep}); err != nil || !ok {
		t.Fatalf("UpdateHeartbeat: %v %v", ok, err)
	}
	a, err = repo.GetByID(ctx, id)
	if err != nil || a.LocalPolicy == nil || a.LocalPolicy.Digest != digest || a.LocalPolicy.Summary.TargetsAllow != 2 ||
		a.LocalPolicyReportedAt == nil {
		t.Fatalf("stored %+v at %v err %v", a.LocalPolicy, a.LocalPolicyReportedAt, err)
	}

	// A heartbeat without a report keeps it.
	if _, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, CPUPercent: 3}); err != nil {
		t.Fatal(err)
	}
	if a, _ = repo.GetByTenantAndID(ctx, tenantID, id); a.LocalPolicy == nil || a.LocalPolicy.Digest != digest {
		t.Fatalf("a heartbeat without a report dropped it: %+v", a.LocalPolicy)
	}

	// The manifest path: written for the tenant's active sensor only.
	paused := *rep
	paused.KillSwitch = true
	if ok, err := repo.UpdateLocalPolicy(ctx, &tenantID, id, &paused); err != nil || !ok {
		t.Fatalf("UpdateLocalPolicy: %v %v", ok, err)
	}
	if a, _ = repo.GetByTenantAndID(ctx, tenantID, id); !a.LocalPolicy.KillSwitch {
		t.Fatalf("kill switch not stored: %+v", a.LocalPolicy)
	}
	other := shared.NewID()
	if ok, err := repo.UpdateLocalPolicy(ctx, &other, id, rep); err != nil || ok {
		t.Fatalf("another tenant wrote it: %v %v", ok, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.UpdateLocalPolicy(ctx, &tenantID, id, rep); err != nil || ok {
		t.Fatalf("a revoked sensor's report was written: %v %v", ok, err)
	}

	// The column only takes a JSON object.
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET reported_local_policy = '[]'::jsonb WHERE id = $1`, id.String()); err == nil {
		t.Fatal("a non-object report was accepted")
	}
}
