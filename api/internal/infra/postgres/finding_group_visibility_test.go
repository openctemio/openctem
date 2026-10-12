package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The group / related-CVE / bulk-by-filter builder honors the same
// visibility fields as the findings list, numbering after the other filters.
func TestBuildFilterWhere_VisibilityRules(t *testing.T) {
	tid, uid := shared.NewID(), shared.NewID()
	f := vulnerability.NewFindingFilter().WithCVEIDs([]string{"CVE-2024-12345"}).
		WithDataScope(&shared.DataScope{TenantID: tid, UserID: uid}).
		WithPentestMemberOrNonPentest(uid)
	f.TenantID = &tid

	where, args := buildFilterWhere(f, 2)
	for _, want := range []string{
		"f.cve_id = ANY($2)",
		"f.pentest_campaign_id IN (\n\t\t\tSELECT campaign_id FROM pentest_campaign_members WHERE user_id = $3 AND tenant_id = $4",
		"f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $5 AND uaa.tenant_id = $6)",
	} {
		if !strings.Contains(where, want) {
			t.Errorf("where missing %q:\n%s", want, where)
		}
	}
	if strings.Contains(where, "NOT EXISTS (SELECT 1 FROM user_accessible_assets") {
		t.Errorf("a resolved scope must be strict:\n%s", where)
	}
	if len(args) != 5 || args[1] != uid.String() || args[2] != tid.String() || args[3] != uid.String() || args[4] != tid.String() {
		t.Errorf("args = %v", args)
	}

	// A bare user scope is strict too: there is no fail-open bypass for a
	// user with no scope row (owner decision D2).
	bare := vulnerability.NewFindingFilter().WithDataScopeUserID(uid)
	bare.TenantID = &tid
	if where, _ := buildFilterWhere(bare, 2); strings.Contains(where, "NOT EXISTS (SELECT 1 FROM user_accessible_assets") ||
		!strings.Contains(where, "f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $2 AND uaa.tenant_id = $3)") {
		t.Errorf("bare user scope must be strict:\n%s", where)
	}

	// A visibility rule without a tenant cannot be resolved: match nothing.
	noTenant := vulnerability.NewFindingFilter().WithDataScopeUserID(uid)
	if where, args := buildFilterWhere(noTenant, 2); where != "FALSE" || len(args) != 0 {
		t.Errorf("no tenant: where=%q args=%v, want FALSE", where, args)
	}

	// No visibility fields: unchanged.
	if where, args := buildFilterWhere(vulnerability.NewFindingFilter(), 2); where != "" || len(args) != 0 {
		t.Errorf("empty filter: where=%q args=%v", where, args)
	}
}
