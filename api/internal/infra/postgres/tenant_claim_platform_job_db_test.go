package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A job queued for shared sensors (is_platform_job) is never offered to, or
// claimable by, an organization's own sensor: not by the poll, not by the
// batch claim, not by the claim by id, and the doorbell does not count it.
// Before, the tenant poll had no such filter, so the routing decision
// "shared sensors" was silently overridden and the tenant's sensor ran the
// job (live: every platform job ever queued ran on a tenant sensor).
// Requires DATABASE_URL.
func TestTenantClaim_NeverTakesPlatformJobs(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)

	own := seedZoneSensor(ctx, t, sqlDB, &tenant, "own", zoneSensorOpts{tools: []string{"nuclei"}})
	// A shared sensor (no tenant) asked for on this tenant's poll: it is not
	// the tenant's sensor, so it is offered and may claim nothing of it.
	sharedRow := seedZoneSensor(ctx, t, sqlDB, &tenant, "shared", zoneSensorOpts{tools: []string{"nuclei"}, platform: true})

	tenantJob := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "nuclei")
	platformJob := createPlatformCommand(ctx, t, cmds, tenant, "nuclei")

	for name, sensor := range map[string]shared.ID{"own sensor": own, "shared sensor": sharedRow} {
		isOwn := sensor == own
		got := polledIDs(ctx, t, cmds, tenant, sensor)
		if got[platformJob] {
			t.Errorf("%s: the tenant poll offered a job queued for shared sensors", name)
		}
		if got[tenantJob] != isOwn {
			t.Errorf("%s: the tenant poll offered the tenant's own job: %v, want %v", name, got[tenantJob], isOwn)
		}
		if isOwn {
			assertPollParity(ctx, t, cmds, tenant, sensor, nil, 1)
		}

		claimed, err := cmds.ClaimManyForSensor(ctx, tenant, sensor, nil, []shared.ID{platformJob})
		if err != nil {
			t.Fatal(err)
		}
		if len(claimed) != 0 {
			t.Errorf("%s: batch claim took a job queued for shared sensors", name)
		}
		if ok, err := cmds.ClaimForSensor(ctx, tenant, platformJob, sensor.String()); err != nil || ok {
			t.Errorf("%s: claim by id took a job queued for shared sensors: ok=%v err=%v", name, ok, err)
		}
	}
	// Nor may the shared sensor take the tenant's own job.
	if claimed, err := cmds.ClaimManyForSensor(ctx, tenant, sharedRow, nil, []shared.ID{tenantJob}); err != nil || len(claimed) != 0 {
		t.Errorf("shared sensor batch-claimed the tenant's job: %d %v", len(claimed), err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, tenantJob, sharedRow.String()); err != nil || ok {
		t.Errorf("shared sensor claimed the tenant's job by id: ok=%v err=%v", ok, err)
	}

	// A poll without a sensor identity does not see it either.
	anon, err := cmds.GetPendingForSensor(ctx, tenant, nil, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range anon {
		if c.ID == platformJob {
			t.Error("anonymous poll offered a job queued for shared sensors")
		}
	}

	// The job is still pending and unassigned: only a shared-sensor claim may take it.
	var status string
	var sensorID *string
	if err := sqlDB.QueryRowContext(ctx, `SELECT status, sensor_id FROM commands WHERE id = $1`,
		platformJob.String()).Scan(&status, &sensorID); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || sensorID != nil {
		t.Errorf("platform job after tenant claims: status=%s sensor_id=%v; want pending, none", status, sensorID)
	}
}

// createPlatformCommand queues an unpinned scan for shared sensors.
func createPlatformCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenantID shared.ID, scanner string) shared.ID {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": scanner, "targets": []string{uniqueTestHost()}})
	cmd, err := command.NewCommand(tenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.SetPlatformJob(50); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create platform command: %v", err)
	}
	return cmd.ID
}
