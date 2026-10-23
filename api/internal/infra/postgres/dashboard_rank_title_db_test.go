package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// findings.title is nullable. A ranked finding without one must come back
// with a fallback title, not fail the whole Fix next list.
func TestDashboardRank_FindingWithoutTitle_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	fid := seedFactFinding(ctx, t, db, tenant, factFinding{
		asset: &asset, severity: "high", priority: "P1", status: "new", slaStatus: "on_track",
		source: "sast", detectedAgo: "1 day",
	})
	if _, err := db.ExecContext(ctx, `UPDATE findings SET title = NULL, rule_id = 'rule.no-title' WHERE id = $1`, fid.String()); err != nil {
		t.Fatalf("clear title: %v", err)
	}
	facts := NewDashboardFactsRepository(&DB{DB: db})
	if _, err := facts.RebuildTenant(ctx, tenant, 2); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	repo := NewDashboardWidgetRepository(&DB{DB: db})
	scope := dashboard.ReadScope{TenantID: tenant}

	items, err := repo.Rank(ctx, scope, dashboard.RankFixNext, dashboard.WidgetFilter{}, 10)
	if err != nil {
		t.Fatalf("rank with a NULL title must not fail: %v", err)
	}
	if len(items) != 1 || items[0].FindingID != fid || items[0].Title != "rule.no-title" {
		t.Fatalf("items = %+v, want the finding titled by its rule id", items)
	}

	// No rule id either: the message is the last resort.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET rule_id = NULL, cve_id = NULL WHERE id = $1`, fid.String()); err != nil {
		t.Fatal(err)
	}
	items, err = repo.Rank(ctx, scope, dashboard.RankFixNext, dashboard.WidgetFilter{}, 10)
	if err != nil || len(items) != 1 || items[0].Title != "msg" {
		t.Fatalf("items = %+v err = %v, want message fallback", items, err)
	}
}
