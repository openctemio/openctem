package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestFindingRemediationKeyRepository_RoundTrip exercises the remediation-group
// side-table + its GROUP BY/rollup and exclusion SQL against the real findings
// schema. Skipped unless DATABASE_URL is set.
func TestFindingRemediationKeyRepository_RoundTrip(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := shared.NewID()
	slug := "remgrp-" + tenantID.String()[:8]
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "rem-group-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	asset1 := seedAsset(ctx, t, db, tenantID)
	asset2 := seedAsset(ctx, t, db, tenantID)

	// Group "sol:openssl": two open findings on two assets (critical + high) +
	// one already-resolved (must be excluded from rollup and resolve) + one
	// pentest finding (excluded).
	fOpen1 := seedFinding(ctx, t, db, tenantID, asset1, "external", "critical", "new")
	fOpen2 := seedFinding(ctx, t, db, tenantID, asset2, "external", "high", "confirmed")
	fClosed := seedFinding(ctx, t, db, tenantID, asset1, "external", "medium", "resolved")
	fPentest := seedFinding(ctx, t, db, tenantID, asset1, "pentest", "high", "new")

	repo := NewFindingRemediationKeyRepository(&DB{DB: db})
	for _, id := range []shared.ID{fOpen1, fOpen2, fClosed, fPentest} {
		if err := repo.Upsert(ctx, tenantID, id, "sol:openssl", "Upgrade OpenSSL"); err != nil {
			t.Fatalf("upsert key: %v", err)
		}
	}

	excl := []string{"resolved", "false_positive", "accepted", "duplicate"}

	groups, err := repo.ListGroups(ctx, tenantID, excl)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0]
	if g.Key != "sol:openssl" || g.Title != "Upgrade OpenSSL" {
		t.Errorf("group key/title mismatch: %+v", g)
	}
	// Only the two OPEN, non-pentest findings count.
	if g.FindingCount != 2 {
		t.Errorf("expected finding_count 2 (open, non-pentest), got %d", g.FindingCount)
	}
	if g.AssetCount != 2 {
		t.Errorf("expected asset_count 2, got %d", g.AssetCount)
	}
	if g.SeverityCounts["critical"] != 1 || g.SeverityCounts["high"] != 1 {
		t.Errorf("severity rollup wrong: %+v", g.SeverityCounts)
	}

	ids, err := repo.OpenFindingIDs(ctx, tenantID, "sol:openssl", excl)
	if err != nil {
		t.Fatalf("open finding ids: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 open finding IDs (excludes resolved + pentest), got %d", len(ids))
	}
}

func seedAsset(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		id.String(), tenantID.String(), "asset-"+id.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func seedFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, source, severity, status string) shared.ID {
	t.Helper()
	id := shared.NewID()
	fp := id.String()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, $4, 'test', 'msg', $5, $6, $7)`,
		id.String(), tenantID.String(), assetID.String(), source, severity, fp, status); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}
