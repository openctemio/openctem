package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Group by CVE must return exactly one group per CVE. It used to GROUP BY the
// CVE together with the finding's severity and catalog columns, so findings of
// one CVE that differ in severity (or in catalog link) became several groups
// with the same group_key: the UI rendered duplicate React keys, the page held
// fewer distinct CVEs than its size, and the counts were split.
func TestListFindingGroups_CVE_OneGroupPerCVE(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	a1 := seedOwnedAsset(ctx, t, db, tenantID, nil)
	a2 := seedOwnedAsset(ctx, t, db, tenantID, nil)

	const cve = "CVE-2099-6387"
	seedGroupFinding(ctx, t, db, tenantID, a1, cve, "medium", nil)
	seedGroupFinding(ctx, t, db, tenantID, a2, cve, "critical", nil)
	seedGroupFinding(ctx, t, db, tenantID, a1, "CVE-2099-0100", "low", nil)

	res, err := repo.ListFindingGroups(ctx, tenantID, "cve_id", vulnerability.FindingFilter{}, pagination.New(1, 100))
	if err != nil {
		t.Fatalf("ListFindingGroups: %v", err)
	}

	seen := map[string]int{}
	var group *vulnerability.FindingGroup
	for _, g := range res.Data {
		seen[g.GroupKey]++
		if g.GroupKey == cve {
			group = g
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("group %s returned %d times, want once", k, n)
		}
	}
	if res.Total != int64(len(seen)) {
		t.Errorf("total = %d, distinct groups on the page = %d", res.Total, len(seen))
	}
	if group == nil {
		t.Fatalf("no group for %s", cve)
	}
	if group.Stats.Total != 2 || group.Stats.AffectedAssets != 2 {
		t.Errorf("stats = %+v, want 2 findings on 2 assets in one group", group.Stats)
	}
	if group.Severity != "critical" {
		t.Errorf("severity = %q, want the worst of the CVE's findings (critical)", group.Severity)
	}
	// Worst-first order: the critical CVE comes before the low one.
	if len(res.Data) < 2 || res.Data[0].GroupKey != cve {
		t.Errorf("first group = %v, want %s (critical first)", res.Data[0].GroupKey, cve)
	}
}
