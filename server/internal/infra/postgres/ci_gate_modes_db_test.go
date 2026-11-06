package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A gate policy's modes round-trip and are tenant-scoped. Requires DATABASE_URL.
func TestCIGatePolicyModes(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()
	p := &cirun.GatePolicy{ID: shared.NewID(), TenantID: tenant, ScopeType: cirun.ScopeRepository, ScopeID: &asset,
		Enabled: true, Mode: cirun.ModeEnforce, FailOnSeverity: "high", NewFindingsOnly: true,
		Modes: cirun.PolicyModes{Capabilities: map[string]string{"sast": cirun.FindingModeComment},
			Rules: map[string]string{"CVE-1": cirun.FindingModeMonitor}}, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateGatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GatePoliciesFor(ctx, tenant, asset)
	if err != nil || len(got) != 1 || got[0].Modes.Capabilities["sast"] != cirun.FindingModeComment ||
		got[0].Modes.Rules["CVE-1"] != cirun.FindingModeMonitor {
		t.Fatalf("policies = %+v %v", got, err)
	}
	p.Modes = cirun.PolicyModes{}
	if err := repo.UpdateGatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GatePoliciesFor(ctx, tenant, asset); len(got[0].Modes.Capabilities) != 0 {
		t.Fatalf("modes not cleared: %+v", got[0].Modes)
	}
	if got, _ := repo.GatePoliciesFor(ctx, other, asset); len(got) != 0 {
		t.Fatalf("other tenant reads %d policies", len(got))
	}
}
