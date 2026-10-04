package postgres

import (
	"strings"
	"testing"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The data-scope predicate is always fail closed (owner decision D2,
// research doc 15 L-04): there is no "NOT EXISTS ... OR" bypass that let a
// user with no scope row see everything, and a user scope without a tenant
// matches nothing. buildWhereClause is pure (no DB), so the generated SQL is
// asserted.

func TestFindingWhere_DataScopeAlwaysFailClosed(t *testing.T) {
	r := &FindingRepository{}
	tid := shared.NewID()
	uid := shared.NewID()

	f := vulnerability.NewFindingFilter()
	f.TenantID = &tid
	f.DataScopeUserID = &uid
	where, _ := r.buildWhereClause(f)
	if strings.Contains(where, "NOT EXISTS") {
		t.Errorf("the scope must have no NOT EXISTS bypass; got: %s", where)
	}
	if !strings.Contains(where, "asset_id IN (SELECT asset_id FROM user_accessible_assets") {
		t.Errorf("the scope must limit to the accessible assets; got: %s", where)
	}

	noTenant := vulnerability.NewFindingFilter()
	noTenant.DataScopeUserID = &uid
	if where, _ := r.buildWhereClause(noTenant); !strings.Contains(where, "FALSE") {
		t.Errorf("a user scope without a tenant must match nothing; got: %s", where)
	}
}

func TestAssetWhere_DataScopeAlwaysFailClosed(t *testing.T) {
	r := &AssetRepository{}
	tidStr := shared.NewID().String()
	uid := shared.NewID()

	where, _ := r.buildWhereClause(assetdom.Filter{TenantID: &tidStr, DataScopeUserID: &uid})
	if strings.Contains(where, "NOT EXISTS") {
		t.Errorf("the scope must have no NOT EXISTS bypass; got: %s", where)
	}
	if !strings.Contains(where, "a.id IN (SELECT asset_id FROM user_accessible_assets") {
		t.Errorf("the scope must limit assets to the accessible set; got: %s", where)
	}

	if where, _ := r.buildWhereClause(assetdom.Filter{DataScopeUserID: &uid}); !strings.Contains(where, "FALSE") {
		t.Errorf("a user scope without a tenant must match nothing; got: %s", where)
	}
}
