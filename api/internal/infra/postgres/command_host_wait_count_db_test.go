package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis/politeness"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The live shape's wait reason: 1 of the task's 20 hosts is held by a task
// of another run; 21 of its 23 targets can start. Another run's id, or
// another tenant, reads nothing. Requires DATABASE_URL.
func TestRunTaskHostWait_Counts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	sensor := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})
	targets, held := liveShape()
	holder := runningScan(ctx, t, cmds, tenant, sensor, held...)

	run := shared.NewID()
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": targets, "scan_run_id": run.String()})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.HostKeys = politeness.Keys(targets, "")
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	hw, err := svc.RunTaskHostWait(ctx, tenant, run, cmd.ID)
	if err != nil || hw == nil {
		t.Fatalf("host wait %v %v", hw, err)
	}
	if hw.Held != 1 || hw.Total != 20 || hw.Targets != 23 || hw.CanStart != 21 ||
		len(hw.Holders) != 1 || hw.Holders[0].CommandID != holder {
		t.Fatalf("host wait %+v", hw)
	}
	if _, err := svc.RunTaskHostWait(ctx, tenant, shared.NewID(), cmd.ID); err == nil {
		t.Fatal("read through another run's id")
	}
	if _, err := svc.RunTaskHostWait(ctx, other, run, cmd.ID); err == nil {
		t.Fatal("read by another tenant")
	}
}
