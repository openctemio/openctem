package postgres

import (
	"context"
	"testing"
)

// A daily EPSS feed moves the percentile of almost every CVE but the score of
// about 1 %. The refresh must write a finding only when its score moved, and
// must not copy the percentile.
func TestRefreshFindingEPSS_WritesOnScoreChangeOnly(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewScoringRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	same, moved := "CVE-2099-91001", "CVE-2099-91002"
	seedEPSS(ctx, t, db, same, 0.40)
	seedEPSS(ctx, t, db, moved, 0.60)
	seedCVEFinding(ctx, t, db, tenant, asset, same, "new")
	seedCVEFinding(ctx, t, db, tenant, asset, moved, "new")
	// Stored: same score as the catalog but a different percentile; the other
	// finding holds a stale score.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET epss_score = 0.40, epss_percentile = 11 WHERE tenant_id = $1 AND cve_id = $2`, tenant.String(), same); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET epss_score = 0.10, epss_percentile = 12 WHERE tenant_id = $1 AND cve_id = $2`, tenant.String(), moved); err != nil {
		t.Fatal(err)
	}

	xmin := func(cve string) (x string, score, pct float64) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT xmin::text, epss_score, epss_percentile FROM findings WHERE tenant_id = $1 AND cve_id = $2`, tenant.String(), cve).Scan(&x, &score, &pct); err != nil {
			t.Fatal(err)
		}
		return
	}
	sameBefore, _, _ := xmin(same)

	if _, err := repo.RefreshFindingEPSS(ctx); err != nil {
		t.Fatal(err)
	}

	sameAfter, sameScore, samePct := xmin(same)
	if sameAfter != sameBefore || sameScore != 0.40 || samePct != 11 {
		t.Fatalf("a finding whose score did not move was rewritten: xmin %s -> %s, score %v, percentile %v", sameBefore, sameAfter, sameScore, samePct)
	}
	_, movedScore, movedPct := xmin(moved)
	if movedScore != 0.60 {
		t.Fatalf("moved score not refreshed: %v", movedScore)
	}
	if movedPct != 12 {
		t.Fatalf("percentile must not be copied by the refresh, got %v", movedPct)
	}

	// A second run with nothing new writes nothing.
	movedXmin, _, _ := xmin(moved)
	if _, err := repo.RefreshFindingEPSS(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := xmin(moved); again != movedXmin {
		t.Fatalf("second run rewrote an up-to-date finding: xmin %s -> %s", movedXmin, again)
	}
}
