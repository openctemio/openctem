package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// Re-ingesting an existing fingerprint is a re-sighting and should raise
// occurrence_count. The dedup upsert set `occurrence_count =
// EXCLUDED.occurrence_count` — the NEW insert's value, always 1 — so the count
// never moved past 1. Live: max(occurrence_count)=1 across all findings, yet 64
// of them had last_seen_at > created_at (were re-ingested). "Times seen" was a
// dead metric.

func openOccDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping occurrence-count DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func TestCreateBatch_ReIngestIncrementsOccurrenceCount(t *testing.T) {
	ctx := context.Background()
	db := openOccDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	fingerprint := "occ-reingest-probe"
	mkFinding := func(t *testing.T) *vulnerability.Finding {
		t.Helper()
		f, err := vulnerability.NewFinding(
			tenantID, assetID,
			vulnerability.FindingSourceVA,
			"probe-tool",
			vulnerability.SeverityHigh,
			"probe message",
		)
		if err != nil {
			t.Fatalf("new finding: %v", err)
		}
		f.SetFingerprint(fingerprint)
		return f
	}

	// First sighting.
	first := mkFinding(t)
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{first}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM findings WHERE tenant_id = $1 AND fingerprint = $2`, tenantID.String(), fingerprint)
	})

	occ := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT occurrence_count FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
			tenantID.String(), fingerprint).Scan(&n); err != nil {
			t.Fatalf("read occurrence_count: %v", err)
		}
		return n
	}

	if got := occ(); got != 1 {
		t.Fatalf("after first sighting occurrence_count = %d, want 1", got)
	}

	// Re-sighting: same fingerprint, new object → ON CONFLICT.
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{mkFinding(t)}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if got := occ(); got != 2 {
		t.Fatalf("after re-sighting occurrence_count = %d, want 2 — a re-ingested "+
			"finding must count the re-sighting, not reset to the new insert's 1", got)
	}

	// A third sighting keeps climbing (it is + 1, not a toggle).
	if err := repo.CreateBatch(ctx, []*vulnerability.Finding{mkFinding(t)}); err != nil {
		t.Fatalf("third ingest: %v", err)
	}
	if got := occ(); got != 3 {
		t.Fatalf("after third sighting occurrence_count = %d, want 3", got)
	}

	// Exactly one row exists — this is dedup, not duplication.
	var rows int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID.String(), fingerprint).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("row count = %d, want 1: re-ingest must merge, not insert a duplicate", rows)
	}
}
