package unit

// GET /scope/stats coverage (research/53 S-3): counted over the caller's
// data scope, failing closed when the scope cannot be resolved.

import (
	"context"
	"errors"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordingCoverage struct {
	tenant shared.ID
	scope  *shared.DataScope
	out    scopedom.InventoryCoverage
}

func (r *recordingCoverage) CountCoverage(_ context.Context, tenantID shared.ID, ds *shared.DataScope) (scopedom.InventoryCoverage, error) {
	r.tenant, r.scope = tenantID, ds
	return r.out, nil
}

type fixedDataScope struct {
	ds  *shared.DataScope
	err error
}

func (f fixedDataScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return f.ds, f.err
}

func TestScopeStats_CoverageUsesTheCallersDataScope(t *testing.T) {
	tenantID, user := shared.NewID(), shared.NewID()
	svc, _, _, _ := newTestScopeService()
	counter := &recordingCoverage{out: scopedom.InventoryCoverage{InternetFacing: 3, InScope: 1, Internal: 4}}
	ds := &shared.DataScope{TenantID: tenantID, UserID: user}
	svc.SetCoverage(counter, fixedDataScope{ds: ds})

	stats, err := svc.GetStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	if counter.tenant != tenantID || counter.scope != ds {
		t.Fatalf("counted for %v scope %+v", counter.tenant, counter.scope)
	}
	if stats.Coverage != 33.33 || stats.Inventory != counter.out {
		t.Fatalf("stats = %+v", stats)
	}
}

// Without a data scope resolver, or when it fails, nothing is counted: a
// restricted caller must never get tenant-wide numbers.
func TestScopeStats_CoverageFailsClosed(t *testing.T) {
	tenantID := shared.NewID()
	svc, _, _, _ := newTestScopeService()
	counter := &recordingCoverage{out: scopedom.InventoryCoverage{InternetFacing: 9, InScope: 9}}

	svc.SetCoverage(counter, nil)
	if _, err := svc.GetStats(context.Background(), tenantID.String()); err == nil {
		t.Fatal("coverage counted with no data scope resolver")
	}
	svc.SetCoverage(counter, fixedDataScope{err: errors.New("db down")})
	if _, err := svc.GetStats(context.Background(), tenantID.String()); err == nil {
		t.Fatal("coverage counted when the data scope lookup failed")
	}
	if !counter.tenant.IsZero() {
		t.Fatal("the counter ran")
	}
}

func TestInventoryCoveragePercent(t *testing.T) {
	for _, c := range []struct {
		in   scopedom.InventoryCoverage
		want float64
	}{
		{scopedom.InventoryCoverage{}, 0},
		{scopedom.InventoryCoverage{InternetFacing: 4, InScope: 4}, 100},
		{scopedom.InventoryCoverage{InternetFacing: 3, InScope: 2}, 66.67},
		{scopedom.InventoryCoverage{InternetFacing: 0, InScope: 2, Internal: 5}, 0},
	} {
		if got := c.in.Percent(); got != c.want {
			t.Errorf("%+v: %v, want %v", c.in, got, c.want)
		}
	}
}
