package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedDashAsset(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, assetType, subType, status string, risk int) shared.ID {
	t.Helper()
	id := shared.NewID()
	var sub any
	if subType != "-" {
		sub = subType
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status, risk_score) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id.String(), tenantID.String(), "a-"+id.String(), assetType, sub, status, risk); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func seedDashFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, severity, status string, vulnID *shared.ID) {
	t.Helper()
	id := shared.NewID()
	var v any
	if vulnID != nil {
		v = vulnID.String()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, vulnerability_id)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', $4, $5, $6, $7)`,
		id.String(), tenantID.String(), assetID.String(), severity, id.String(), status, v); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

// GetAllStats reads findings and assets once each (GROUPING SETS) instead of
// one scan per CTE. Pin every figure the dashboard shows, tenant-scoped.
func TestDashboardGetAllStats_OnePass(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	repoWith := seedDashAsset(ctx, t, db, tenant, "repository", "github", "active", 40)
	seedDashAsset(ctx, t, db, tenant, "repository", "", "active", 20) // repo without findings; '' sub_type ignored
	host := seedDashAsset(ctx, t, db, tenant, "host", "-", "inactive", 0)
	otherAsset := seedDashAsset(ctx, t, db, other, "repository", "gitlab", "active", 90)

	vulnID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO vulnerabilities (id, cve_id, title, severity, cvss_score) VALUES ($1, $2, 'v', 'high', 8.0)`,
		vulnID.String(), "CVE-2099-"+vulnID.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, vulnID.String())
	})

	seedDashFinding(ctx, t, db, tenant, repoWith, "critical", "new", &vulnID)
	seedDashFinding(ctx, t, db, tenant, repoWith, "high", "confirmed", nil)
	seedDashFinding(ctx, t, db, tenant, host, "high", "resolved", nil)
	seedDashFinding(ctx, t, db, tenant, host, "low", "draft", nil) // excluded (draft)
	seedDashFinding(ctx, t, db, other, otherAsset, "critical", "new", nil)

	s, err := repo.GetAllStats(ctx, tenant, nil)
	if err != nil {
		t.Fatalf("GetAllStats: %v", err)
	}

	if s.Assets.Total != 3 || s.Assets.ByType["repository"] != 2 || s.Assets.ByType["host"] != 1 {
		t.Errorf("asset counts wrong: %+v", s.Assets)
	}
	if s.Assets.ByStatus["active"] != 2 || s.Assets.ByStatus["inactive"] != 1 {
		t.Errorf("asset status wrong: %+v", s.Assets.ByStatus)
	}
	if len(s.Assets.BySubType) != 1 || s.Assets.BySubType["github"] != 1 {
		t.Errorf("asset sub-type wrong (empty/NULL sub_type must be ignored): %+v", s.Assets.BySubType)
	}
	if s.Assets.AverageRiskScore != 20 {
		t.Errorf("avg risk: want 20, got %v", s.Assets.AverageRiskScore)
	}
	if s.Findings.Total != 3 {
		t.Errorf("finding total: want 3 (draft excluded, tenant-scoped), got %d", s.Findings.Total)
	}
	if s.Findings.BySeverity["critical"] != 1 || s.Findings.BySeverity["high"] != 2 || s.Findings.BySeverity["low"] != 0 {
		t.Errorf("finding severity wrong: %+v", s.Findings.BySeverity)
	}
	if s.Findings.ByStatus["new"] != 1 || s.Findings.ByStatus["confirmed"] != 1 || s.Findings.ByStatus["resolved"] != 1 {
		t.Errorf("finding status wrong: %+v", s.Findings.ByStatus)
	}
	if s.Findings.AverageCVSS != 8 {
		t.Errorf("avg cvss: want 8 (only findings with a vulnerability count), got %v", s.Findings.AverageCVSS)
	}
	if s.Repos.Total != 2 || s.Repos.WithFindings != 1 {
		t.Errorf("repos wrong: %+v", s.Repos)
	}
}
