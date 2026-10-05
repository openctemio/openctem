package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// One INSERT ... ON CONFLICT DO UPDATE cannot update the same row twice. A
// batch that carried one conflict key twice failed as a whole, and every other
// row in it was lost with it (RFC-043 P0, docs/architecture/deduplication.md
// probe P18). These tests send such batches through the real repositories on a
// migrated database.

func openBatchDedupDB(t *testing.T) (*sql.DB, *DB) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping batch dedup tests")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db, &DB{DB: db}
}

func seedBatchTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "batch-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

func countBatchRows(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestExposureBulkUpsert_DuplicateFingerprintInBatch(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	repo := NewExposureRepository(pdb)

	mk := func(title string, sev exposure.Severity) *exposure.ExposureEvent {
		e, err := exposure.NewExposureEvent(tenant, exposure.EventTypePortOpen, sev, title, "nmap", map[string]any{"port": 22})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	first := mk("Port 22 open", exposure.SeverityLow)
	time.Sleep(2 * time.Millisecond)
	again := mk("Port 22 open", exposure.SeverityHigh) // same fingerprint, later sighting
	batch := []*exposure.ExposureEvent{first, mk("Port 80 open", exposure.SeverityLow), again, mk("Port 443 open", exposure.SeverityLow)}

	if err := repo.BulkUpsert(ctx, batch); err != nil {
		t.Fatalf("BulkUpsert with a repeated fingerprint failed: %v", err)
	}
	if n := countBatchRows(t, db, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1`, tenant.String()); n != 3 {
		t.Fatalf("rows = %d, want 3 (one per fingerprint)", n)
	}
	var id, sev string
	var firstSeen, lastSeen time.Time
	if err := db.QueryRow(`SELECT id, severity, first_seen_at, last_seen_at FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`,
		tenant.String(), first.Fingerprint()).Scan(&id, &sev, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	// What one-by-one upserts would leave: the first occurrence's identity, the
	// last occurrence's refreshed fields.
	if id != first.ID().String() {
		t.Errorf("id = %s, want the first occurrence's %s", id, first.ID())
	}
	if sev != string(exposure.SeverityHigh) {
		t.Errorf("severity = %s, want the last sighting's high", sev)
	}
	near := func(a, b time.Time) bool { d := a.Sub(b); return d < time.Microsecond && d > -time.Microsecond }
	if !near(lastSeen, again.LastSeenAt()) || !near(firstSeen, first.FirstSeenAt()) {
		t.Errorf("first/last seen = %v/%v, want %v/%v", firstSeen, lastSeen, first.FirstSeenAt(), again.LastSeenAt())
	}
}

func TestUpsertBranchOccurrences_DuplicateFindingInBatch(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	repo := NewFindingRepository(pdb)

	assetID, branchID := shared.NewID(), shared.NewID()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, assetID.String(), tenant.String(), "github.com/acme/"+assetID.String())
	mustExec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, assetID.String())
	mustExec(`INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, 'main', true)`, branchID.String(), assetID.String())
	fps := []string{"fp-occ-a-" + assetID.String(), "fp-occ-b-" + assetID.String()}
	for _, fp := range fps {
		mustExec(`INSERT INTO findings (id, tenant_id, asset_id, title, source, tool_name, message, fingerprint, severity, status)
			VALUES ($1, $2, $3, 'x', 'sast', 'semgrep', 'x', $4, 'high', 'new')`, shared.NewID().String(), tenant.String(), assetID.String(), fp)
	}

	items := []vulnerability.BranchOccurrenceUpsert{
		{Fingerprint: fps[0], BranchID: branchID, ScanID: "scan-1", CommitSHA: "aaa"},
		{Fingerprint: fps[1], BranchID: branchID, ScanID: "scan-1", CommitSHA: "aaa"},
		{Fingerprint: fps[0], BranchID: branchID, ScanID: "scan-1", CommitSHA: "bbb"}, // same finding again
	}
	if _, err := repo.BackfillFindingBranches(ctx, tenant, items); err != nil {
		t.Fatalf("BackfillFindingBranches: %v", err)
	}
	if err := repo.UpsertBranchOccurrences(ctx, tenant, items); err != nil {
		t.Fatalf("UpsertBranchOccurrences with a repeated finding failed: %v", err)
	}
	if n := countBatchRows(t, db, `SELECT count(*) FROM finding_branch_occurrences WHERE tenant_id = $1`, tenant.String()); n != 2 {
		t.Fatalf("occurrences = %d, want 2 (one per finding)", n)
	}
	var commit string
	if err := db.QueryRow(`SELECT o.last_commit_sha FROM finding_branch_occurrences o JOIN findings f ON f.id = o.finding_id WHERE f.fingerprint = $1`, fps[0]).Scan(&commit); err != nil {
		t.Fatal(err)
	}
	if commit != "bbb" {
		t.Errorf("last commit = %s, want the last sighting's bbb", commit)
	}
}

func TestEPSSUpsertBatch_RepeatedCVE(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	repo := &EPSSRepository{db: pdb}
	cve := "CVE-2099-" + shared.NewID().String()[:5]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM epss_scores WHERE cve_id = $1`, cve) })

	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	scores := []*threatintel.EPSSScore{
		threatintel.NewEPSSScore(cve, 0.9, 0.99, "v2025", day.AddDate(0, 0, 1)),
		threatintel.NewEPSSScore(cve, 0.1, 0.10, "v2025", day),
	}
	if err := repo.UpsertBatch(ctx, scores); err != nil {
		t.Fatalf("EPSS sync with a repeated CVE failed: %v", err)
	}
	var score float64
	if err := db.QueryRow(`SELECT epss_score FROM epss_scores WHERE cve_id = $1`, cve).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != 0.9 {
		t.Errorf("score = %v, want the newest score date's 0.9", score)
	}
}

func TestMarkDispatched_RepeatedAsset(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	assetID := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, assetID.String(), tenant.String(), "h-"+assetID.String()); err != nil {
		t.Fatal(err)
	}
	repo := NewScanCoverageRepository(pdb)
	if err := repo.MarkDispatched(ctx, scancoverage.DispatchRecord{TenantID: tenant, AssetIDs: []string{assetID.String(), assetID.String()}}); err != nil {
		t.Fatalf("MarkDispatched with a repeated asset failed: %v", err)
	}
	if n := countBatchRows(t, db, `SELECT count(*) FROM scan_coverage_state WHERE asset_id = $1`, assetID.String()); n != 1 {
		t.Fatalf("coverage rows = %d, want 1", n)
	}
}

func TestDedupeLastWins(t *testing.T) {
	got := dedupeLastWins([]string{"a1", "b1", "a2", "c1", "b2"}, func(s string) string { return s[:1] })
	want := []string{"a2", "b2", "c1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
