package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// The live incident, replayed: a continuous coverage DNS resolution (a
// single-scanner dnsx command, built with an empty key list because dnsx
// only queries resolvers) is offered and claimable while an HTTP probe of
// the tenant holds the same names, and while it runs it holds back no
// active scan of them. Before, it carried the keys of its names, waited
// behind every port, HTTP and template scan for an hour and was ended as
// "no sensor picked up this run's work". Requires DATABASE_URL.
func TestCommandHostKeys_PassiveCommandNeverWaitsOrHolds(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"httpx", "dnsx"}})
	foreign := seedZoneSensor(ctx, t, sqlDB, &other, "f", zoneSensorOpts{tools: []string{"httpx", "dnsx"}})

	httpx := createHostChunk(ctx, t, cmds, tenant, "a.example.com", "b.example.com")
	if ok, err := cmds.ClaimForSensor(ctx, tenant, httpx, s.String()); err != nil || !ok {
		t.Fatalf("httpx chunk not claimed: %v %v", ok, err)
	}

	raw, _ := json.Marshal(map[string]any{"scanner": "dnsx", "scanner_name": "dnsx",
		"targets": []string{"a.example.com", "b.example.com"}, "step_key": "quick_scan"})
	dnsx, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityLow, raw)
	if err != nil {
		t.Fatal(err)
	}
	dnsx.HostKeys = []string{} // as the scan service builds a passive command
	if err := cmds.Create(ctx, dnsx); err != nil {
		t.Fatal(err)
	}
	if col, sent := storedHostKeys(ctx, t, cmds, dnsx.ID); len(col) != 0 || len(sent) != 0 {
		t.Fatalf("passive command stored keys column=%v payload=%v, want none", col, sent)
	}

	if !polledIDs(ctx, t, cmds, tenant, s)[dnsx.ID] {
		t.Fatal("passive command not offered while an active scan holds its names")
	}
	if polledIDs(ctx, t, cmds, other, foreign)[dnsx.ID] {
		t.Fatal("another organization's sensor was offered the command")
	}
	if ok, err := cmds.ClaimForSensor(ctx, other, dnsx.ID, foreign.String()); err == nil && ok {
		t.Fatal("another organization's sensor claimed the command")
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, dnsx.ID, s.String()); err != nil || !ok {
		t.Fatalf("passive command not claimable while its names are held: %v %v", ok, err)
	}

	// The passive command now runs: an active chunk on the same names is
	// held back only by the httpx chunk, not by it.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, httpx.String()); err != nil {
		t.Fatal(err)
	}
	next := createHostChunk(ctx, t, cmds, tenant, "a.example.com")
	if !polledIDs(ctx, t, cmds, tenant, s)[next] {
		t.Fatal("an active chunk waited behind a running passive command")
	}
}
