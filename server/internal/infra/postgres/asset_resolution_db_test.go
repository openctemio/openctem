package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Resolution states: consecutive failures make a name not_resolving, a
// resolution brings it back, and another tenant's names are never read or
// written.
func TestAssetResolution_StatesAndIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetResolutionRepository(&DB{DB: sqlDB})
	a, b := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	mk := func(tenant shared.ID, name string) shared.ID {
		id := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'subdomain', 'active')`,
			id.String(), tenant.String(), name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	gone, other := mk(a, "gone.example.com"), mk(b, "gone.example.com")
	now := time.Now().Add(-time.Hour)

	// One failure is a resolver hiccup, two in a row is a fact.
	if err := repo.RecordFailedNames(ctx, a, []string{"gone.example.com"}, now, assetresolution.SourceSensorRefusal); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.NotResolving(ctx, a, []string{"gone.example.com"}); got["gone.example.com"] {
		t.Fatal("one failed check made the name not_resolving")
	}
	if err := repo.RecordFailedNames(ctx, a, []string{"gone.example.com"}, now.Add(time.Minute), assetresolution.SourceSensorRefusal); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.NotResolving(ctx, a, []string{"gone.example.com", "never.example.com"}); err != nil || !got["gone.example.com"] || len(got) != 1 {
		t.Fatalf("not resolving = %v %v", got, err)
	}
	// The same report twice counts once.
	_ = repo.RecordFailedNames(ctx, a, []string{"gone.example.com"}, now.Add(time.Minute), assetresolution.SourceSensorRefusal)
	if r, _ := repo.Get(ctx, a, gone); r == nil || r.Failures != 2 || r.State != assetresolution.StateNotResolving {
		t.Fatalf("state = %+v", r)
	}

	// Tenant b's same-named asset is untouched and unreadable through a.
	if got, _ := repo.NotResolving(ctx, b, []string{"gone.example.com"}); len(got) != 0 {
		t.Fatalf("tenant b sees tenant a's state: %v", got)
	}
	if r, _ := repo.Get(ctx, b, other); r != nil {
		t.Fatalf("tenant b's asset has a state: %+v", r)
	}
	if r, _ := repo.Get(ctx, b, gone); r != nil {
		t.Fatalf("tenant a's state read as tenant b: %+v", r)
	}
	// An id of another tenant writes nothing.
	if err := repo.RecordFailed(ctx, b, []shared.ID{gone}, time.Now(), assetresolution.SourceResolveStage); err != nil {
		t.Fatal(err)
	}
	if r, _ := repo.Get(ctx, a, gone); r.Failures != 2 {
		t.Fatalf("tenant b changed tenant a's state: %+v", r)
	}

	// It comes back when it resolves again.
	if err := repo.RecordResolved(ctx, a, []shared.ID{gone}, time.Now()); err != nil {
		t.Fatal(err)
	}
	r, _ := repo.Get(ctx, a, gone)
	if r == nil || r.State != assetresolution.StateResolving || r.Failures != 0 || r.ResolvedAt == nil {
		t.Fatalf("after resolving: %+v", r)
	}
	if got, _ := repo.NotResolving(ctx, a, []string{"gone.example.com"}); len(got) != 0 {
		t.Fatalf("still not resolving: %v", got)
	}
	// The list filter follows the state.
	cond := assetResolutionCondition("not_resolving")
	var n int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND `+cond, a.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("filter matches %d resolving names", n)
	}
	_ = repo.RecordFailed(ctx, a, []shared.ID{gone}, time.Now().Add(time.Minute), assetresolution.SourceResolveStage)
	_ = repo.RecordFailed(ctx, a, []shared.ID{gone}, time.Now().Add(2*time.Minute), assetresolution.SourceResolveStage)
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND `+cond, a.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("filter matches %d, want 1", n)
	}
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND `+cond, b.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("filter leaks across tenants: %d", n)
	}
}

// Of a step's skipped targets, the names that no longer resolve are counted:
// a batch whose listed refusals are all unresolvable counts its whole total.
func TestStepBatchState_Unresolvable(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	add := func(result map[string]any) {
		raw, _ := json.Marshal(result)
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO commands (id, tenant_id, type, status, payload, result, scan_run_step_id, completed_at)
			VALUES ($1, $2, 'scan', 'completed', '{}', $3, $4, NOW())`,
			shared.NewID().String(), tenant.String(), raw, stepRun.String()); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(h string) map[string]string { return map[string]string{"target": h, "reason": "unresolvable"} }
	// 157 refused, ten listed, all unresolvable.
	var listed []map[string]string
	for i := 0; i < 10; i++ {
		listed = append(listed, gone("h.example.com"))
	}
	add(map[string]any{"metadata": map[string]any{"refused_targets": listed, "refused_targets_total": 157}})
	// A mixed batch counts only the listed unresolvable ones.
	add(map[string]any{"metadata": map[string]any{"refused_targets": []any{gone("a.example.com"), map[string]string{"target": "*.x", "reason": "wildcard_pattern"}}, "refused_targets_total": 40}})
	b, err := cmds.StepBatchState(ctx, tenant, stepRun)
	if err != nil {
		t.Fatal(err)
	}
	if b.Skipped != 197 || b.Unresolvable != 158 {
		t.Fatalf("skipped %d unresolvable %d, want 197 and 158", b.Skipped, b.Unresolvable)
	}
	// Another tenant's step reads none of it.
	other := seedTestTenant(ctx, t, sqlDB)
	if ob, err := cmds.StepBatchState(ctx, other, stepRun); err != nil || ob.Total != 0 || ob.Unresolvable != 0 {
		t.Fatalf("other tenant: %+v %v", ob, err)
	}
}
