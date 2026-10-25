package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A command of a scan run that has ended is never
// claimed. Canceling or timing out a run cancels the commands that exist at
// that moment; a step transition that read the run as running just before
// could still create the next step's commands afterwards, and a sensor then
// scanned for a run the user had stopped. Only a run of the command's own
// tenant decides; a command naming no such run is unaffected. Requires
// DATABASE_URL.
func TestClaim_SkipsCommandsOfClosedRuns(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	sensor := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})

	run := func(owner shared.ID, status string) string {
		var id string
		if err := sqlDB.QueryRowContext(ctx, `
			INSERT INTO scan_runs (tenant_id, trigger_type, status, kind)
			VALUES ($1, 'manual', $2, 'retest') RETURNING id`, owner.String(), status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	command := func(runID string) shared.ID {
		id := newLeaseTestCommand(ctx, t, cmds, tenant)
		if runID != "-" {
			if _, err := sqlDB.ExecContext(ctx,
				`UPDATE commands SET payload = jsonb_set(COALESCE(payload, '{}'::jsonb), '{scan_run_id}', to_jsonb($2::text)) WHERE id = $1`,
				id.String(), runID); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}

	cases := []struct {
		name  string
		runID string
		want  bool
	}{
		{"no run", "-", true},
		{"pending run", run(tenant, "pending"), true},
		{"running run", run(tenant, "running"), true},
		{"canceled run", run(tenant, "canceled"), false},
		{"timed out run", run(tenant, "timeout"), false},
		{"failed run", run(tenant, "failed"), false},
		{"completed run", run(tenant, "completed"), false},
		{"another tenant's ended run", run(other, "canceled"), true},
		{"unknown run", shared.NewID().String(), true},
		{"not a uuid", "not-a-uuid", true},
		{"blocked run", run(tenant, "blocked"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name+" (claim by id)", func(t *testing.T) {
			id := command(tc.runID)
			ok, err := cmds.ClaimForSensor(ctx, tenant, id, sensor.String())
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Fatalf("claimed = %v, want %v", ok, tc.want)
			}
		})
		t.Run(tc.name+" (batch claim)", func(t *testing.T) {
			id := command(tc.runID)
			got, err := cmds.ClaimManyForSensor(ctx, tenant, sensor, nil, []shared.ID{id})
			if err != nil {
				t.Fatal(err)
			}
			if claimed := len(got) == 1; claimed != tc.want {
				t.Fatalf("claimed = %v, want %v", claimed, tc.want)
			}
		})
	}
}
