package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// step_params round-trips through create, update and read, and an update
// with another tenant's id changes nothing (the update is tenant-bound).
func TestScanStepParams_RoundTripAndTenantBound(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanRepository(&DB{DB: db})
	victim := seedScanRecTenant(ctx, t, db)
	attacker := seedScanRecTenant(ctx, t, db)

	sc, err := scan.NewScanWithTargets(victim, "step params scan", []string{"example.com"}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.ScannerName = "nuclei"
	if err := sc.SetStepParams(scan.StepParams{"*:vuln.templates": {"severity": []string{"high"}}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String())
	})
	got, err := repo.GetByTenantAndID(ctx, victim, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sev, _ := got.StepParams["*:vuln.templates"]["severity"].([]any); len(sev) != 1 || sev[0] != "high" {
		t.Fatalf("step_params = %v", got.StepParams)
	}

	// Another tenant's id: not found, row unchanged.
	evil := *got
	evil.TenantID = attacker
	evil.StepParams = scan.StepParams{"*:vuln.templates": {"severity": []string{"info"}}}
	if err := repo.Update(ctx, &evil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update err = %v, want not found", err)
	}
	again, _ := repo.GetByTenantAndID(ctx, victim, sc.ID)
	if sev, _ := again.StepParams["*:vuln.templates"]["severity"].([]any); sev[0] != "high" {
		t.Fatalf("another tenant changed step_params: %v", again.StepParams)
	}

	// The owner clears them.
	_ = again.SetStepParams(nil)
	if err := repo.Update(ctx, again); err != nil {
		t.Fatal(err)
	}
	cleared, _ := repo.GetByTenantAndID(ctx, victim, sc.ID)
	if len(cleared.StepParams) != 0 {
		t.Fatalf("not cleared: %v", cleared.StepParams)
	}
}
