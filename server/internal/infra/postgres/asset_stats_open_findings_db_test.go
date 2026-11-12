package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The inventory stats count open findings only: the same set as each row's
// finding_count and the has_findings filter. Closed and dispositioned
// findings, branch-only findings and another tenant's findings never count.
func TestAssetAggregateStats_CountsOpenFindingsOnly(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db).String()
	other := seedTestTenant(ctx, t, db).String()
	now := time.Now().UTC()

	open := insertCTEMAsset(t, db, tenant, "open", "", false, "", "", now)
	closedOnly := insertCTEMAsset(t, db, tenant, "closed-only", "", false, "", "", now)
	otherAsset := insertCTEMAsset(t, db, other, "other", "", false, "", "", now)

	finding := func(tenantID, assetID, status string, branchOnly bool) {
		fp := "fp-stats-open-" + shared.NewID().String()
		mustExec(t, db,
			`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint)
			 VALUES ($1,$2,'sast','tool','msg','high',$3,$4)`,
			tenantID, assetID, status, fp)
		if branchOnly {
			// The insert trigger derives branch_only from the branch columns;
			// set it the way a feature-branch scan leaves it.
			mustExec(t, db, `UPDATE findings SET branch_only = TRUE WHERE tenant_id = $1 AND fingerprint = $2`, tenantID, fp)
		}
	}
	// Two open findings on one asset...
	finding(tenant, open, "new", false)
	finding(tenant, open, "in_progress", false)
	// ...and every closed, dispositioned or branch-only kind next to them.
	finding(tenant, open, "resolved", false)
	finding(tenant, open, "false_positive", false)
	finding(tenant, open, "accepted", false)
	finding(tenant, open, "new", true)
	finding(tenant, closedOnly, "resolved", false)
	finding(tenant, closedOnly, "false_positive", false)
	// Another organization's open findings.
	finding(other, otherAsset, "new", false)
	finding(other, otherAsset, "confirmed", false)

	stats, err := repo.GetAggregateStats(ctx, shared.MustIDFromString(tenant), asset.AccessScope{}, nil, nil, nil, "")
	if err != nil {
		t.Fatalf("GetAggregateStats: %v", err)
	}
	checkCount(t, "total", stats.Total, 2)
	checkCount(t, "with_findings", stats.WithFindings, 1)
	checkCount(t, "findings_total", stats.FindingsTotal, 2)
}
