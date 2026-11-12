package postgres

import (
	"context"
	"testing"
	"time"

	commandapp "github.com/openctemio/openctem/server/internal/app/command"
	sensorapp "github.com/openctemio/openctem/server/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The heartbeat doorbell against a real schema for work the claim splits
// (live 2026-11-04). Requires DATABASE_URL.

func ringFor(ctx context.Context, d *sensorapp.Doorbell, tenant, sensor shared.ID) sensordom.HeartbeatHints {
	return d.Ring(ctx, sensorapp.DoorbellRequest{Identity: sensorapp.SensorIdentity{
		Sensor: &sensordom.Sensor{ID: sensor, TenantID: &tenant, Status: sensordom.SensorStatusActive},
	}})
}

// A run step's task waits for one host another task holds on two of its 23
// targets. The idle sensor's claim would split it and start the 21 others,
// so the doorbell tells the sensor there is work (before: pending_jobs=0,
// and the sensor took it only on its safety poll), and the claim that
// follows takes it. Another organization's sensor is never told about it.
func TestDoorbell_RingsForAHostSplit(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	cfg := sensorapp.DefaultDoorbellConfig().Normalized(5*time.Minute, 0)
	plain := sensorapp.NewDoorbell(cmds, cfg, logger.NewNop())
	d := sensorapp.NewDoorbell(cmds, cfg, logger.NewNop())
	d.SetHostSplits(svc)

	tenant, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	busy := seedZoneSensor(ctx, t, sqlDB, &tenant, "busy", zoneSensorOpts{tools: []string{"nuclei"}})
	idle := seedZoneSensor(ctx, t, sqlDB, &tenant, "idle", zoneSensorOpts{tools: []string{"nuclei"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	targets, held := liveShape()
	runningScan(ctx, t, cmds, tenant, busy, held...)
	waiting := stepScan(ctx, t, cmds, tenant, stepRun, targets...)

	if h := ringFor(ctx, plain, tenant, idle); h.PendingJobs != 0 {
		t.Fatalf("fixture: the all-hosts-free count sees %d", h.PendingJobs)
	}
	if h := ringFor(ctx, d, tenant, idle); h.PendingJobs != 1 {
		t.Fatalf("doorbell pending_jobs=%d for a task the claim would split, want 1", h.PendingJobs)
	}
	// Reading the count changes nothing.
	if rows := stepRows(ctx, t, sqlDB, tenant, stepRun); len(rows) != 1 || rows[0].splits != 0 {
		t.Fatalf("the doorbell split the task: %+v", rows)
	}
	// Tenant isolation: another organization's sensor is neither told nor
	// counted, and its own (identical) holder changes nothing for it.
	runningScan(ctx, t, cmds, other, o, held...)
	if h := ringFor(ctx, d, other, o); h.PendingJobs != 0 {
		t.Fatalf("another organization's sensor told of %d jobs", h.PendingJobs)
	}
	if n, err := svc.HostSplitReady(ctx, other, o, nil); err != nil || n != 0 {
		t.Fatalf("another organization's split count: %d %v", n, err)
	}
	// A sensor id of another organization asked under this tenant sees nothing
	// (the sensor gates join the sensor in the command's tenant).
	if n, err := svc.HostSplitReady(ctx, tenant, o, nil); err != nil || n != 0 {
		t.Fatalf("a foreign sensor's split count in the tenant: %d %v", n, err)
	}

	// The ring is honest: the claim that follows takes the split task.
	got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: idle.String(), MaxJobs: 2, Limit: 2})
	if err != nil || len(got) != 1 || got[0].ID != waiting {
		t.Fatalf("claim after the ring: %v %d", err, len(got))
	}
	// What waits now (the blocked part) cannot start: no ring.
	if h := ringFor(ctx, d, tenant, idle); h.PendingJobs != 0 {
		t.Fatalf("pending_jobs=%d with only the blocked part left", h.PendingJobs)
	}
}

// A task most of whose targets are busy waits whole: the claim would not
// split it, so the doorbell does not ring for it.
func TestDoorbell_NoRingForATaskThatWaitsWhole(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	d := sensorapp.NewDoorbell(cmds, sensorapp.DefaultDoorbellConfig().Normalized(5*time.Minute, 0), logger.NewNop())
	d.SetHostSplits(svc)

	tenant := seedTestTenant(ctx, t, sqlDB)
	busy := seedZoneSensor(ctx, t, sqlDB, &tenant, "busy", zoneSensorOpts{tools: []string{"nuclei"}})
	idle := seedZoneSensor(ctx, t, sqlDB, &tenant, "idle", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	runningScan(ctx, t, cmds, tenant, busy, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	stepScan(ctx, t, cmds, tenant, stepRun, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")

	if h := ringFor(ctx, d, tenant, idle); h.PendingJobs != 0 {
		t.Fatalf("pending_jobs=%d for a task that waits whole", h.PendingJobs)
	}
	if got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: idle.String(), MaxJobs: 2, Limit: 2}); err != nil || len(got) != 0 {
		t.Fatalf("claim: %v %d (the doorbell and the claim must agree)", err, len(got))
	}
}
