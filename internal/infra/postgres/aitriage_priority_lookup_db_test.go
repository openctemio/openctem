package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestAITriagePriorityLookupRepo_GetFalsePositiveVerdicts verifies, against
// app_test, that the lookup returns a high-confidence false-positive verdict only
// for the LATEST completed triage clearing the threshold — and that a newer,
// below-threshold triage supersedes an older high-confidence one.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestAITriagePriorityLookupRepo_GetFalsePositiveVerdicts(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "aitriage-fp-test", "aitfp-"+tenantID.String()[:8])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })

	// Asset.
	var assetIDStr string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,$3) RETURNING id`,
		tenantID.String(), "web-01", "domain").Scan(&assetIDStr); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	// Three findings on the asset.
	fpHigh := insertFinding(t, db, tenantID.String(), assetIDStr, "high-conf FP")
	fpSuperseded := insertFinding(t, db, tenantID.String(), assetIDStr, "superseded FP")
	fpLow := insertFinding(t, db, tenantID.String(), assetIDStr, "low-conf")
	noTriage := insertFinding(t, db, tenantID.String(), assetIDStr, "never triaged")

	now := time.Now().UTC()

	// fpHigh: one completed triage, fp=0.9 → returned.
	insertTriage(t, db, tenantID.String(), fpHigh, "completed", 0.9, now)

	// fpSuperseded: OLD completed fp=0.95, then NEWER completed fp=0.1 → the newer
	// (below threshold) verdict wins → NOT returned.
	insertTriage(t, db, tenantID.String(), fpSuperseded, "completed", 0.95, now.Add(-time.Hour))
	insertTriage(t, db, tenantID.String(), fpSuperseded, "completed", 0.1, now)

	// fpLow: completed fp=0.5 (< 0.8) → NOT returned.
	insertTriage(t, db, tenantID.String(), fpLow, "completed", 0.5, now)

	// A pending high-fp triage must be ignored (only 'completed' counts).
	insertTriage(t, db, tenantID.String(), fpLow, "pending", 0.99, now.Add(time.Minute))

	repo := NewAITriagePriorityLookupRepo(db)
	ids := []shared.ID{mustID(t, fpHigh), mustID(t, fpSuperseded), mustID(t, fpLow), mustID(t, noTriage)}
	got, err := repo.GetFalsePositiveVerdicts(ctx, tenantID, ids)
	if err != nil {
		t.Fatalf("GetFalsePositiveVerdicts: %v", err)
	}

	if v, ok := got[mustID(t, fpHigh)]; !ok || !v.Likely || v.Likelihood != 0.9 {
		t.Fatalf("fpHigh: want Likely@0.9, got %+v (present=%v)", v, ok)
	}
	if _, ok := got[mustID(t, fpSuperseded)]; ok {
		t.Fatalf("fpSuperseded: newer below-threshold verdict must supersede; want absent, got present")
	}
	if _, ok := got[mustID(t, fpLow)]; ok {
		t.Fatalf("fpLow: below threshold + pending ignored; want absent, got present")
	}
	if _, ok := got[mustID(t, noTriage)]; ok {
		t.Fatalf("noTriage: no completed triage; want absent, got present")
	}
}

func insertFinding(t *testing.T, db *sql.DB, tenantID, assetID, msg string) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(context.Background(),
		`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		 VALUES ($1,$2,'sca','trivy',$3,'critical',$4,'new') RETURNING id`,
		tenantID, assetID, msg, "fp-"+shared.NewID().String()).Scan(&id); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

func insertTriage(t *testing.T, db *sql.DB, tenantID, findingID, status string, fpLikelihood float64, createdAt time.Time) {
	t.Helper()
	mustExec(t, db,
		`INSERT INTO ai_triage_results (tenant_id, finding_id, triage_type, status, false_positive_likelihood, created_at, updated_at)
		 VALUES ($1,$2,'auto',$3,$4,$5,$5)`,
		tenantID, findingID, status, fpLikelihood, createdAt)
}

func mustID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatalf("parse id %q: %v", s, err)
	}
	return id
}
