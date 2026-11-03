package programfeed

import (
	"context"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type scopeOffTenants map[string]bool

func (o scopeOffTenants) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if o[tenantID] {
		return map[string]bool{moduledom.ModuleScopeConfig: true}
	}
	return nil
}

// The subscribed programs of a tenant with the scope module off are not
// updated from the catalog; the other tenants' programs are.
func TestReconcile_SkipsTenantWithScopeOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	cat := &memCatalog{stale: []bp.ProgramRef{
		{TenantID: off, ProgramID: shared.NewID()},
		{TenantID: on, ProgramID: shared.NewID()},
	}}
	subs := &memSubs{}
	imp := NewImporter(DirSource("."), cat, subs, "root", nil)
	imp.SetModuleGuard(scopeOffTenants{off.String(): true})
	imp.Reconcile(context.Background())
	if subs.applied != 1 {
		t.Fatalf("expected one program updated (the tenant with scope on), got %d", subs.applied)
	}
}
