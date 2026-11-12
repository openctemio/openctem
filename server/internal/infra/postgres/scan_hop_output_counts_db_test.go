package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The run map counts what each step produced by asset type, within the
// tenant, and, for a caller with a data scope, only the assets in it.
func TestScanHops_CountStepOutputs(t *testing.T) {
	db := openHopDB(t)
	ctx := context.Background()
	repo := NewScanHopRepository(&DB{DB: db})
	a := newHopTenant(t, db, 3)
	b := newHopTenant(t, db, 1)
	ip := shared.NewID()
	hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, '10.1.2.3', 'ip_address')`, ip, a.tenant)
	for _, asset := range append(append([]shared.ID{}, a.assets...), ip) {
		hopExec(t, db, `INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
			a.tenant, a.run, a.stepRun, asset)
	}
	hopExec(t, db, `INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
		b.tenant, b.run, b.stepRun, b.assets[0])

	counts := func(tenant, run shared.ID, scope *shared.DataScope) map[string]int {
		t.Helper()
		got, err := repo.CountStepOutputs(ctx, tenant, run, scope)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, c := range got {
			if c.StepRunID != a.stepRun && c.StepRunID != b.stepRun {
				t.Fatalf("count for an unknown step run %s", c.StepRunID)
			}
			out[c.AssetType] += c.Count
		}
		return out
	}

	if got := counts(a.tenant, a.run, nil); got["subdomain"] != 3 || got["ip_address"] != 1 || len(got) != 2 {
		t.Fatalf("unrestricted counts = %v", got)
	}
	// Cross-tenant: tenant B's id reads nothing of tenant A's run.
	if got := counts(b.tenant, a.run, nil); len(got) != 0 {
		t.Fatalf("other tenant read %v", got)
	}

	// A member who may see one subdomain only counts that one.
	user := seedGroupsUser(ctx, t, db, "run-map.test")
	addTenantMember(ctx, t, db, a.tenant, user)
	hopExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user, a.tenant, a.assets[0])
	scope := &shared.DataScope{TenantID: a.tenant, UserID: user}
	if got := counts(a.tenant, a.run, scope); got["subdomain"] != 1 || got["ip_address"] != 0 {
		t.Fatalf("scoped counts = %v, want one subdomain", got)
	}

	// A deleted asset is no longer counted.
	hopExec(t, db, `UPDATE assets SET deleted_at = now() WHERE id = $1`, ip)
	if got := counts(a.tenant, a.run, nil); got["ip_address"] != 0 {
		t.Fatalf("deleted asset still counted: %v", got)
	}
}
