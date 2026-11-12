package postgres

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Why a task waits for its hosts (research/130): how many of its hosts the
// tenant's running tasks hold and which tasks (run, step, tool), never
// another tenant's, and not a host its holder already released. The run
// tasks list flags the wait. Requires DATABASE_URL.
func TestPlacement_HostWait(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx", "naabu"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"httpx"}})
	sfx := uniqueTestHostSuffix()
	h1, h2, h3 := "h1-"+sfx, "h2-"+sfx, "h3-"+sfx

	holder := func(tn, sensor shared.ID, tool, runID, step string, keys ...string) shared.ID {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"scanner": tool, "targets": keys, "scan_run_id": runID, "step_key": step})
		cmd, err := command.NewCommand(tn, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		cmd.HostKeys = keys
		if err := cmds.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		if ok, err := cmds.ClaimForSensor(ctx, tn, cmd.ID, sensor.String()); err != nil || !ok {
			t.Fatalf("claim holder: %v %v", ok, err)
		}
		return cmd.ID
	}
	runA := shared.NewID().String()
	httpx := holder(tenant, a, "httpx", runA, "http", h1, h2)
	// Another tenant's task on the third host: never counted or named.
	holder(other, o, "httpx", shared.NewID().String(), "http", h3)
	// A range holder of a bucket the waiting task has an address in.
	naabu := holder(tenant, a, "naabu", runA, "ports", "net:192.0.2.0/24")

	waiting := createHostChunk(ctx, t, cmds, tenant, h1, h2, h3, "192.0.2.9", "in:192.0.2.0/24")

	p, err := svc.ExplainPlacement(ctx, tenant, waiting)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.JobReasons, command.PlacementHostBusy) || p.HostWait == nil {
		t.Fatalf("placement %+v", p)
	}
	hw := p.HostWait
	if hw.Total != 4 || hw.Held != 3 {
		t.Fatalf("held %d of %d, want 3 of 4 (h1, h2, the address in the range; not the other tenant's h3)", hw.Held, hw.Total)
	}
	if len(hw.Holders) != 2 || hw.Holders[0].CommandID != httpx || hw.Holders[0].Tool != "httpx" ||
		hw.Holders[0].RunID != runA || hw.Holders[0].StepKey != "http" || hw.Holders[1].CommandID != naabu {
		t.Fatalf("holders %+v", hw.Holders)
	}

	// httpx released h1 and h2: only the range holds the address now.
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{
		httpx.String(): {Done: 2, Total: 2, ReleasedKeys: []string{h1, h2}},
	}); err != nil {
		t.Fatal(err)
	}
	p, _ = svc.ExplainPlacement(ctx, tenant, waiting)
	if p.HostWait == nil || p.HostWait.Held != 1 || len(p.HostWait.Holders) != 1 || p.HostWait.Holders[0].CommandID != naabu {
		t.Fatalf("after release: %+v", p.HostWait)
	}

	// The run tasks list flags the wait.
	tasks, _, err := cmds.ListRunTasks(ctx, tenant, shared.MustIDFromString(runA), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range tasks {
		if tk.WaitingOnHosts {
			t.Fatalf("a running task %s flagged as waiting on hosts", tk.ID)
		}
	}

	// The range ends: nothing holds the task back, no host wait.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, naabu.String()); err != nil {
		t.Fatal(err)
	}
	p, _ = svc.ExplainPlacement(ctx, tenant, waiting)
	if p.HostWait != nil || slices.Contains(p.JobReasons, command.PlacementHostBusy) {
		t.Fatalf("free task: %+v", p)
	}

	// Another tenant cannot read it.
	if _, _, err := cmds.HostHolders(ctx, other, waiting, 3); err == nil {
		t.Fatal("another tenant read the host holders")
	}
}

// A run task that waits on its hosts is flagged in the run's task list.
func TestListRunTasks_WaitingOnHosts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	host := "w-" + uniqueTestHostSuffix()
	holderID := createHostChunk(ctx, t, cmds, tenant, host)
	if ok, err := cmds.ClaimForSensor(ctx, tenant, holderID, a.String()); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	runID := shared.NewID()
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{host}, "scan_run_id": runID.String(), "step_key": "quick_scan"})
	cmd, _ := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	cmd.HostKeys = []string{host}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	tasks, _, err := cmds.ListRunTasks(ctx, tenant, runID, 10)
	if err != nil || len(tasks) != 1 || !tasks[0].WaitingOnHosts {
		t.Fatalf("tasks %+v (%v)", tasks, err)
	}
}

// A sensor that hands a task back for its own per-host limit stores one
// code, and the placement names it while the platform sees the hosts free.
func TestRelease_HostsBusyCode(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	id := createHostChunk(ctx, t, cmds, tenant, "r-"+uniqueTestHostSuffix())
	if ok, err := cmds.ClaimForSensor(ctx, tenant, id, a.String()); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if _, err := svc.Release(ctx, commandapp.ReleaseInput{TenantID: tenant.String(), SensorID: a.String(),
		CommandID: id.String(), Reason: "its hosts are busy on this sensor"}); err != nil {
		t.Fatal(err)
	}
	got, err := cmds.GetByTenantAndID(ctx, tenant, id)
	if err != nil || got.ErrorMessage != command.ReleasedBySensorPrefix+command.ReleaseReasonHostsBusy {
		t.Fatalf("stored %q (%v)", got.ErrorMessage, err)
	}
	p, err := svc.ExplainPlacement(ctx, tenant, id)
	if err != nil || !slices.Equal(p.JobReasons, []string{command.PlacementSensorHostsBusy}) {
		t.Fatalf("job reasons %v (%v)", p.JobReasons, err)
	}
}
