package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The storage of the claim-time scope re-check against a real schema: the
// dispatch-gate record round-trips, and both outcome writes apply only to a
// pending command of the right tenant still as the re-check read it (so a
// second or concurrent re-check never records twice). Requires DATABASE_URL.
func TestCommandScopeRecheck_Storage(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	create := func(tenantID shared.ID, gate *command.DispatchGate) *command.Command {
		t.Helper()
		cmd, err := command.NewCommand(tenantID, command.CommandTypeScan, command.CommandPriorityNormal,
			json.RawMessage(`{"scanner":"httpx","targets":["a.example.com","b.example.com"],"timeout_seconds":60}`))
		if err != nil {
			t.Fatal(err)
		}
		cmd.DispatchGate = gate
		if err := repo.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		got, err := repo.GetByTenantAndID(ctx, tenantID, cmd.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	rec := &command.DispatchGate{Tier: 2, Passive: false, ActScope: true, Actor: shared.NewID().String()}
	c := create(tenant, rec)
	if c.DispatchGate == nil || *c.DispatchGate != *rec {
		t.Fatalf("dispatch gate read back as %+v, want %+v", c.DispatchGate, rec)
	}
	if none := create(tenant, nil); none.DispatchGate != nil {
		t.Fatalf("no record read back as %+v", none.DispatchGate)
	}

	narrowed := json.RawMessage(`{"scanner":"httpx","targets":["a.example.com"],"timeout_seconds":60}`)
	// Another tenant's id never matches.
	foreign := *c
	foreign.TenantID = other
	if ok, err := repo.NarrowPendingPayload(ctx, &foreign, narrowed); err != nil || ok {
		t.Fatalf("narrowed across tenants: %v %v", ok, err)
	}
	if ok, err := repo.FailPending(ctx, &foreign, "SCOPE_CHANGED: x"); err != nil || ok {
		t.Fatalf("failed across tenants: %v %v", ok, err)
	}
	if ok, err := repo.NarrowPendingPayload(ctx, c, narrowed); err != nil || !ok {
		t.Fatalf("narrow: %v %v", ok, err)
	}
	// A second narrowing from the same (now stale) read does not apply.
	if ok, err := repo.NarrowPendingPayload(ctx, c, json.RawMessage(`{"targets":[]}`)); err != nil || ok {
		t.Fatalf("stale narrow applied: %v %v", ok, err)
	}
	got, _ := repo.GetByTenantAndID(ctx, tenant, c.ID)
	var p struct {
		Targets []string `json:"targets"`
	}
	_ = json.Unmarshal(got.Payload, &p)
	if len(p.Targets) != 1 || p.Targets[0] != "a.example.com" || got.Status != command.CommandStatusPending {
		t.Fatalf("stored after narrowing: %s %s", got.Status, got.Payload)
	}

	if ok, err := repo.FailPending(ctx, got, "SCOPE_CHANGED: a.example.com (excluded)"); err != nil || !ok {
		t.Fatalf("fail: %v %v", ok, err)
	}
	if ok, err := repo.FailPending(ctx, got, "SCOPE_CHANGED: again"); err != nil || ok {
		t.Fatalf("failed twice: %v %v", ok, err)
	}
	got, _ = repo.GetByTenantAndID(ctx, tenant, c.ID)
	if got.Status != command.CommandStatusFailed || got.ErrorMessage != "SCOPE_CHANGED: a.example.com (excluded)" || got.CompletedAt == nil {
		t.Fatalf("stored after failing: %s %q", got.Status, got.ErrorMessage)
	}
}
