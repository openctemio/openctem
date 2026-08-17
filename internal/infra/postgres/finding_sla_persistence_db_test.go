package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// SLA was dead end-to-end because the computed deadline was never persisted.
// The applier (internal/app/sla/applier.go) called SetSLADeadline in memory,
// but the findings INSERT column list, its argument block, the ON CONFLICT set,
// the generic Update(), and the reconstruct path all omitted sla_deadline /
// sla_status. Live proof at the time: 0 of 188 rows had a non-NULL deadline, so
// the 15-min escalation controller (which requires sla_deadline IS NOT NULL) and
// the dashboard breach counter always read 0.
//
// These tests write a finding with a deadline through the repository and read it
// back — the only thing that catches a column that is set in memory but never
// stored. They fail before the column additions (the deadline reads back NULL)
// and pass after.

func openSLADB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping sla persistence round-trip")
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

// A finding created with a future deadline must come back with that deadline
// stored (not NULL) and sla_status = on_track. Before the fix the deadline read
// back NULL and the status defaulted to not_applicable.
func TestCreate_PersistsSLADeadline(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

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
	f.SetFingerprint("sla-future-" + f.ID().String())

	// 30 days out → on_track. SetSLADeadline recomputes sla_status, exactly
	// what the ingest applier does before the batch INSERT.
	deadline := time.Now().UTC().Add(30 * 24 * time.Hour)
	f.SetSLADeadline(deadline)
	if f.SLAStatus() != vulnerability.SLAStatusOnTrack {
		t.Fatalf("precondition: expected on_track in memory, got %q", f.SLAStatus())
	}

	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	// DB-level truth: the column is actually non-NULL. This is the assertion
	// that was 0-for-188 in production.
	var notNull bool
	if err := db.QueryRowContext(ctx,
		`SELECT sla_deadline IS NOT NULL FROM findings WHERE id = $1`, f.ID().String()).Scan(&notNull); err != nil {
		t.Fatalf("query sla_deadline: %v", err)
	}
	if !notNull {
		t.Fatal("sla_deadline stored NULL — the computed deadline was dropped on write (the end-to-end SLA bug)")
	}

	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.SLADeadline() == nil {
		t.Fatal("sla_deadline read back nil — reconstruct discarded the persisted value")
	}
	if !got.SLADeadline().Truncate(time.Millisecond).Equal(deadline.Truncate(time.Millisecond)) {
		t.Errorf("sla_deadline round-trip: got %v, want %v", got.SLADeadline(), deadline)
	}
	if got.SLAStatus() != vulnerability.SLAStatusOnTrack {
		t.Errorf("sla_status round-trip: got %q, want on_track", got.SLAStatus())
	}
	// Neighbors: a shifted placeholder would land here.
	if got.Source() != vulnerability.FindingSourceVA {
		t.Errorf("source: got %q, want va", got.Source())
	}
	if got.Severity() != vulnerability.SeverityHigh {
		t.Errorf("severity: got %q, want high", got.Severity())
	}
}

// A past deadline on an open finding must persist as overdue — the same value
// the escalation controller now writes, so the two agree.
func TestCreate_PersistsSLAOverdue(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	f, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityCritical, "probe message",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetFingerprint("sla-overdue-" + f.ID().String())

	f.SetSLADeadline(time.Now().UTC().Add(-48 * time.Hour)) // past → overdue
	if f.SLAStatus() != vulnerability.SLAStatusOverdue {
		t.Fatalf("precondition: expected overdue in memory, got %q", f.SLAStatus())
	}

	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The DB CHECK constraint (migration 000012) only permits the enum values;
	// 'overdue' passes, 'breached' would have failed the insert entirely.
	var status string
	if err := db.QueryRowContext(ctx,
		`SELECT sla_status FROM findings WHERE id = $1`, f.ID().String()).Scan(&status); err != nil {
		t.Fatalf("query sla_status: %v", err)
	}
	if status != string(vulnerability.SLAStatusOverdue) {
		t.Errorf("sla_status: got %q, want overdue", status)
	}
}

// Update() must persist a recomputed SLA deadline. The reclassifier tightens the
// deadline on priority escalation and persists via Update(); before the fix the
// UPDATE omitted both SLA columns, so the tightened deadline never took effect.
func TestUpdate_PersistsSLADeadline(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	f, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityHigh, "probe message",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetFingerprint("sla-update-" + f.ID().String())
	if err := repo.Create(ctx, f); err != nil { // created with no deadline
		t.Fatalf("create: %v", err)
	}

	// Now set a deadline and persist via Update (reclassifier path).
	deadline := time.Now().UTC().Add(7 * 24 * time.Hour)
	f.SetSLADeadline(deadline)
	if err := repo.Update(ctx, f); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.SLADeadline() == nil {
		t.Fatal("Update() dropped the recomputed sla_deadline")
	}
	if got.SLAStatus() != vulnerability.SLAStatusOnTrack {
		t.Errorf("sla_status after update: got %q, want on_track", got.SLAStatus())
	}
}

// The re-ingest enrichment path (EnrichBatchByFingerprints) must not wipe a
// finding's persisted deadline. EnrichFrom preserves it, and the enrich column
// set now carries it, so a re-ingest keeps SLA intact.
func TestEnrichBatch_PreservesSLADeadline(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	fp := "sla-enrich-fp"
	f, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityHigh, "probe message",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetFingerprint(fp)
	deadline := time.Now().UTC().Add(14 * 24 * time.Hour)
	f.SetSLADeadline(deadline)
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	// A new scan reports the same finding (same fingerprint) with fresh data
	// but no SLA — mirrors a normal re-ingest.
	newData, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityCritical, "updated message",
	)
	if err != nil {
		t.Fatalf("new finding (rescan): %v", err)
	}
	newData.SetFingerprint(fp)

	if _, err := repo.EnrichBatchByFingerprints(ctx, tenantID, []*vulnerability.Finding{newData}, "scan-x"); err != nil {
		t.Fatalf("enrich: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.SLADeadline() == nil {
		t.Fatal("re-ingest enrichment wiped the persisted sla_deadline")
	}
	if !got.SLADeadline().Truncate(time.Millisecond).Equal(deadline.Truncate(time.Millisecond)) {
		t.Errorf("sla_deadline after enrich: got %v, want %v", got.SLADeadline(), deadline)
	}
	// Enrichment still applied its own data.
	if got.Severity() != vulnerability.SeverityCritical {
		t.Errorf("enrich should have raised severity to critical, got %q", got.Severity())
	}
}

// enrichColumnsPerRow MUST equal len(enrichColumnDefs) and match collectEnrichArgs,
// or the batch VALUES clause and its flattened args disagree and the UPDATE writes
// data into the wrong columns. No database required.
func TestEnrichColumns_CountsAgree(t *testing.T) {
	if enrichColumnsPerRow != len(enrichColumnDefs) {
		t.Fatalf("enrichColumnsPerRow=%d but len(enrichColumnDefs)=%d", enrichColumnsPerRow, len(enrichColumnDefs))
	}

	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSAST, "t", vulnerability.SeverityLow, "m",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	args, err := collectEnrichArgs(f)
	if err != nil {
		t.Fatalf("collectEnrichArgs: %v", err)
	}
	if len(args) != enrichColumnsPerRow {
		t.Errorf("collectEnrichArgs returns %d values, enrichColumnsPerRow=%d", len(args), enrichColumnsPerRow)
	}
	// Assert the SLA columns are present in the def set.
	var hasDeadline, hasStatus bool
	for _, c := range enrichColumnDefs {
		switch c.name {
		case "sla_deadline":
			hasDeadline = true
		case "sla_status":
			hasStatus = true
		}
	}
	if !hasDeadline || !hasStatus {
		t.Errorf("enrichColumnDefs missing sla columns: deadline=%v status=%v", hasDeadline, hasStatus)
	}
}
