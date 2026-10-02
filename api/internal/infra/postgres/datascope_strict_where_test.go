package postgres

import (
	"strings"
	"testing"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// Data-scope fail-open vs fail-closed. buildWhereClause is pure (no DB), so we
// assert the generated SQL: strict drops the `NOT EXISTS ... OR` bypass so a user
// with no accessible assets matches nothing (Tenable "No Access"); non-strict
// keeps the bypass (backward-compatible fail-open).

func TestFindingWhere_DataScopeFailOpenVsClosed(t *testing.T) {
	r := &FindingRepository{}
	tid := shared.NewID()
	uid := shared.NewID()

	base := vulnerability.NewFindingFilter()
	base.TenantID = &tid
	base.DataScopeUserID = &uid

	open := base
	open.DataScopeStrict = false
	whereOpen, _ := r.buildWhereClause(open)
	if !strings.Contains(whereOpen, "NOT EXISTS") {
		t.Errorf("fail-open must keep NOT EXISTS bypass; got: %s", whereOpen)
	}

	strict := base
	strict.DataScopeStrict = true
	whereStrict, _ := r.buildWhereClause(strict)
	if strings.Contains(whereStrict, "NOT EXISTS") {
		t.Errorf("fail-closed must drop the NOT EXISTS bypass; got: %s", whereStrict)
	}
	if !strings.Contains(whereStrict, "asset_id IN (SELECT asset_id FROM user_accessible_assets") {
		t.Errorf("fail-closed must still scope to accessible assets; got: %s", whereStrict)
	}
}

func TestAssetWhere_DataScopeFailOpenVsClosed(t *testing.T) {
	r := &AssetRepository{}
	tidStr := shared.NewID().String()
	uid := shared.NewID()

	base := assetdom.Filter{TenantID: &tidStr, DataScopeUserID: &uid}

	open := base
	open.DataScopeStrict = false
	whereOpen, _ := r.buildWhereClause(open)
	if !strings.Contains(whereOpen, "NOT EXISTS") {
		t.Errorf("fail-open must keep NOT EXISTS bypass; got: %s", whereOpen)
	}

	strict := base
	strict.DataScopeStrict = true
	whereStrict, _ := r.buildWhereClause(strict)
	if strings.Contains(whereStrict, "NOT EXISTS") {
		t.Errorf("fail-closed must drop the NOT EXISTS bypass; got: %s", whereStrict)
	}
	if !strings.Contains(whereStrict, "a.id IN (SELECT asset_id FROM user_accessible_assets") {
		t.Errorf("fail-closed must still scope assets to accessible set; got: %s", whereStrict)
	}
}
