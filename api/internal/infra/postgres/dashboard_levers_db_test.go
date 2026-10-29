package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedLeverSuggestion(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, title, state string, stored int, members ...shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.String())
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO remediation_suggestions (id, tenant_id, kind, algorithm, algorithm_version, action_key, key_kind, title,
			identity, finding_ids, member_count, risk_points, confidence, state)
		VALUES ($1, $2, 'new_group', 'test', 1, $3, 'package', $4, $5, $6::uuid[], $7, $8, 0.9, $9)`,
		id.String(), tenant.String(), "pkg:"+id.String(), title, id.String()[:32], pq.Array(ids), len(ids), stored, state); err != nil {
		t.Fatalf("seed suggestion: %v", err)
	}
	return id
}

// TopFix re-counts suggestions in the read's scope: open members only, in
// the data scope, no pentest finding, one tenant.
func TestDashboardTopFix_ScopeTenantAndPentest_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardWidgetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	mine := seedDashAsset(ctx, t, db, tenant, "host", "-", "active", 10)
	theirs := seedDashAsset(ctx, t, db, tenant, "host", "-", "active", 10)
	otherAsset := seedDashAsset(ctx, t, db, other, "host", "-", "active", 10)
	campaign := seedFactCampaign(ctx, t, db, tenant)

	open := func(asset shared.ID, prio string) shared.ID {
		return seedFactFinding(ctx, t, db, tenant, factFinding{asset: &asset, severity: "high", priority: prio, status: "confirmed", slaStatus: "not_applicable",
			source: "sca", detectedAgo: "2 days"})
	}
	// A: two open findings on my asset (P0, P1) and one fixed -> 2 findings, 12 points.
	a1, a2 := open(mine, "P0"), open(mine, "P1")
	aFixed := seedFactFinding(ctx, t, db, tenant, factFinding{asset: &mine, severity: "high", priority: "P0", status: "resolved", slaStatus: "not_applicable",
		source: "sca", detectedAgo: "9 days", resolvedAgo: "1 day"})
	sugA := seedLeverSuggestion(ctx, t, db, tenant, "Upgrade libA", "proposed", 12, a1, a2, aFixed)
	// B: more stored points, but its findings are on the other asset (outside the member's scope).
	b1, b2, b3 := open(theirs, "P0"), open(theirs, "P0"), open(theirs, "P1")
	sugB := seedLeverSuggestion(ctx, t, db, tenant, "Upgrade libB", "proposed", 20, b1, b2, b3)
	// C: only pentest findings (on my asset), 24 points: it would win both
	// reads if pentest findings counted; never a lever.
	pentest := func() shared.ID {
		return seedFactFinding(ctx, t, db, tenant, factFinding{asset: &mine, severity: "critical", priority: "P0", status: "confirmed",
			slaStatus: "not_applicable", source: "pentest", campaign: &campaign, detectedAgo: "2 days"})
	}
	seedLeverSuggestion(ctx, t, db, tenant, "Patch pentest finding", "proposed", 99, pentest(), pentest(), pentest())
	// D: dismissed: never a lever.
	seedLeverSuggestion(ctx, t, db, tenant, "Dismissed fix", "dismissed", 100, open(mine, "P0"))
	// Another tenant's suggestion naming this tenant's findings matches nothing.
	o1 := seedFactFinding(ctx, t, db, other, factFinding{asset: &otherAsset, severity: "critical", priority: "P0", status: "confirmed", slaStatus: "not_applicable",
		source: "sca", detectedAgo: "2 days"})
	seedLeverSuggestion(ctx, t, db, other, "Other tenant fix", "proposed", 500, o1, a1, a2)

	// Organization read: B clears the most points.
	org, err := repo.TopFix(ctx, dashboard.ReadScope{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	if org == nil || org.SuggestionID != sugB || org.Findings != 3 || org.Assets != 1 || org.PriorityOpen != 3 || org.Points != 20 {
		t.Fatalf("org top fix %+v", org)
	}

	// A member who sees only "mine": B has no visible member, the pentest
	// fix is left out, A counts its two open findings.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'lever')`,
		user.String(), "lever-"+user.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), tenant.String(), mine.String()); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	scoped, err := repo.TopFix(ctx, dashboard.ReadScope{TenantID: tenant, Assets: &shared.DataScope{TenantID: tenant, UserID: user}, CampaignViewer: &user})
	if err != nil {
		t.Fatal(err)
	}
	if scoped == nil || scoped.SuggestionID != sugA || scoped.Findings != 2 || scoped.PriorityOpen != 2 || scoped.Points != 12 || scoped.Title != "Upgrade libA" {
		t.Fatalf("scoped top fix %+v", scoped)
	}

	// A member with no scope row sees no fix at all.
	none, err := repo.TopFix(ctx, dashboard.ReadScope{TenantID: tenant, Assets: &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}})
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatalf("no-scope top fix %+v", none)
	}

	// The other tenant only ever counts its own findings.
	ot, err := repo.TopFix(ctx, dashboard.ReadScope{TenantID: other})
	if err != nil {
		t.Fatal(err)
	}
	if ot == nil || ot.Findings != 1 || ot.Points != 8 {
		t.Fatalf("other tenant top fix %+v", ot)
	}
}
