package command

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GetPendingForSensor must not hand a capability-scoped command to a sensor that
// does not advertise the required capability. This is the claim-time mirror of
// the dispatch-time required_capabilities the validation dispatcher stamps onto
// a validate command: without it, during the live deploy a plain (non-nuclei)
// sensor could race-claim a `validate:nuclei` validate command it cannot run,
// producing a wrong/failed validation outcome.
//
// A command with no required_capabilities must still be returned to any sensor
// (the unchanged behavior for every scan/collect command).
func TestGetPendingForSensor_CapabilityFilter(t *testing.T) {
	ctx := context.Background()
	db := openCommandDB(t)
	repo := postgres.NewCommandRepository(db)
	tenantID := seedExpiryTenant(ctx, t, db)

	// A capability-scoped validate command: only a sensor advertising
	// "validate:nuclei" may claim it.
	nucleiCmd := mustCreateCommand(ctx, t, repo, tenantID,
		commanddom.CommandTypeValidate,
		map[string]any{"required_capabilities": []string{"validate:nuclei"}})

	// An unscoped command: any sensor may claim it.
	plainCmd := mustCreateCommand(ctx, t, repo, tenantID,
		commanddom.CommandTypeScan,
		map[string]any{"scan_run_id": shared.NewID().String()})

	sensorID := shared.NewID()

	// 1. A plain sensor (only "validate") must see the unscoped command but NOT
	//    the nuclei-scoped one.
	got := pendingIDs(ctx, t, repo, tenantID, &sensorID, []string{"validate"})
	if got[nucleiCmd.String()] {
		t.Error("plain 'validate' sensor was offered a 'validate:nuclei'-scoped command it cannot run")
	}
	if !got[plainCmd.String()] {
		t.Error("unscoped command was withheld from a sensor (should go to any sensor)")
	}

	// 2. A nuclei-capable sensor must see BOTH.
	got = pendingIDs(ctx, t, repo, tenantID, &sensorID, []string{"validate", "validate:nuclei"})
	if !got[nucleiCmd.String()] {
		t.Error("nuclei-capable sensor was NOT offered the 'validate:nuclei' command it can run")
	}
	if !got[plainCmd.String()] {
		t.Error("nuclei-capable sensor was withheld the unscoped command")
	}

	// 3. A sensor with no capabilities may still claim the unscoped command, but
	//    never the scoped one.
	got = pendingIDs(ctx, t, repo, tenantID, &sensorID, nil)
	if got[nucleiCmd.String()] {
		t.Error("sensor with no capabilities was offered a capability-scoped command")
	}
	if !got[plainCmd.String()] {
		t.Error("sensor with no capabilities was withheld an unscoped command")
	}
}

func mustCreateCommand(
	ctx context.Context, t *testing.T, repo *postgres.CommandRepository,
	tenantID shared.ID, typ commanddom.CommandType, payload map[string]any,
) shared.ID {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	cmd, err := commanddom.NewCommand(tenantID, typ, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatalf("new command: %v", err)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

func pendingIDs(
	ctx context.Context, t *testing.T, repo *postgres.CommandRepository,
	tenantID shared.ID, sensorID *shared.ID, capabilities []string,
) map[string]bool {
	t.Helper()
	cmds, err := repo.GetPendingForSensor(ctx, tenantID, sensorID, capabilities, 50)
	if err != nil {
		t.Fatalf("GetPendingForSensor: %v", err)
	}
	ids := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		ids[c.ID.String()] = true
	}
	return ids
}
