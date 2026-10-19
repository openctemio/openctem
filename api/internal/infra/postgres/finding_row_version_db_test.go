package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Lost updates on findings (docs/architecture/finding-row-version.md). Every
// finding mutator reads the row, changes it in memory and writes every
// column back. Two concurrent writers used to overwrite each other: a tags
// edit racing a resolve put the old status back, and because that write was
// not a person's move the regression trigger marked a false regression.
// Requires DATABASE_URL.

func seedRowVersionFinding(ctx context.Context, t *testing.T, repo *FindingRepository, tenantID, assetID shared.ID, fp string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityHigh, "probe message")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetFingerprint(fp)
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	return f
}

// Two copies of one finding: copy 1 resolves it, copy 2 (read before the
// resolve) edits tags. The stale tags write must be refused with a conflict;
// the finding stays resolved and is not marked a regression.
func TestFindingUpdate_StaleCopyCannotRevertStatus(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	f := seedRowVersionFinding(ctx, t, repo, tenantID, assetID, "row-version-status-"+shared.NewID().String())

	copy1, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read copy 1: %v", err)
	}
	copy2, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read copy 2: %v", err)
	}

	if err := copy1.TransitionStatus(vulnerability.FindingStatusFixApplied, "patched", nil); err != nil {
		t.Fatalf("fix applied: %v", err)
	}
	if err := copy1.TransitionStatus(vulnerability.FindingStatusResolved, "fixed", nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := repo.Update(ctx, copy1); err != nil {
		t.Fatalf("write copy 1: %v", err)
	}

	copy2.SetTags([]string{"edited"})
	err = repo.Update(ctx, copy2)
	if err == nil || !errors.Is(err, shared.ErrConflict) {
		t.Errorf("stale write: got %v, want a conflict", err)
	}

	var status string
	var isRegression bool
	var reopen int
	if err := db.QueryRowContext(ctx, `SELECT status, COALESCE(is_regression, FALSE), COALESCE(reopen_count, 0)
		FROM findings WHERE id = $1`, f.ID().String()).Scan(&status, &isRegression, &reopen); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != string(vulnerability.FindingStatusResolved) {
		t.Errorf("status = %q after the stale write, want resolved", status)
	}
	if isRegression || reopen != 0 {
		t.Errorf("stale write marked a false regression: is_regression=%v reopen_count=%d", isRegression, reopen)
	}
}

// The conflict carries the stored finding; a write on a fresh read lands and
// the copy then carries the new version, so a second write from it lands too.
func TestFindingUpdate_ConflictCarriesCurrentAndFreshWriteLands(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	f := seedRowVersionFinding(ctx, t, repo, tenantID, assetID, "row-version-current-"+shared.NewID().String())

	stale, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Any other writer (here a narrow one) bumps the version.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET tags = ARRAY['by-other'] WHERE id = $1`, f.ID().String()); err != nil {
		t.Fatalf("other writer: %v", err)
	}
	stale.SetTags([]string{"mine"})
	err = repo.Update(ctx, stale)
	var conflict *vulnerability.FindingConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("got %v, want *FindingConflictError", err)
	}
	if conflict.Current == nil || !slices.Contains(conflict.Current.Tags(), "by-other") ||
		conflict.Current.RowVersion() != stale.RowVersion()+1 {
		t.Errorf("conflict should carry the stored finding at the next version, got %+v", conflict.Current)
	}

	fresh, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	fresh.SetTags([]string{"by-other", "mine"})
	if err := repo.Update(ctx, fresh); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	fresh.SetTags([]string{"by-other", "mine", "again"})
	if err := repo.Update(ctx, fresh); err != nil {
		t.Fatalf("second write from the same copy: %v", err)
	}

	// A caller that named a version it saw is refused when the copy moved on.
	expCtx := vulnerability.WithExpectedRowVersion(ctx, f.ID(), stale.RowVersion())
	again, _ := repo.GetByID(ctx, tenantID, f.ID())
	again.SetTags(nil)
	if err := repo.Update(expCtx, again); !vulnerability.IsFindingConflict(err) {
		t.Errorf("If-Match on an old version: got %v, want a conflict", err)
	}
}

// A versioned write of another tenant's finding id answers not found, never
// conflict (the conflict lookup is tenant-scoped, so nothing of the other
// tenant's row is revealed).
func TestFindingUpdate_OtherTenantIsNotFoundNotConflict(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA := seedTestAsset(ctx, t, db, tenantA)
	f := seedRowVersionFinding(ctx, t, repo, tenantA, assetA, "row-version-tenant-"+shared.NewID().String())

	// A copy claiming tenant B for tenant A's finding id.
	stored, err := repo.GetByID(ctx, tenantA, f.ID())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	forged := vulnerability.ReconstituteFinding(vulnerability.FindingData{
		ID: f.ID(), TenantID: tenantB, AssetID: assetA, Source: vulnerability.FindingSourceVA,
		ToolName: "probe-tool", Severity: vulnerability.SeverityLow, Message: "forged",
		Status: vulnerability.FindingStatusInProgress,
	})
	forged.RestoreRowVersion(stored.RowVersion())
	err = repo.Update(ctx, forged)
	if !errors.Is(err, shared.ErrNotFound) || vulnerability.IsFindingConflict(err) {
		t.Errorf("other tenant's id: got %v, want not found", err)
	}
	after, _ := repo.GetByID(ctx, tenantA, f.ID())
	if after.Message() != "probe message" || after.RowVersion() != stored.RowVersion() {
		t.Errorf("tenant A's finding changed: message=%q version=%d", after.Message(), after.RowVersion())
	}
}

// Ingest enrichment reads the stored rows, merges a sighting and writes the
// merged rows back. It must not write columns other writers own (an analyst's
// priority override, the SLA deadline), and a row another writer changed
// between the read and the write is read and merged again.
func TestEnrichBatch_KeepsConcurrentWrites(t *testing.T) {
	db := openSLADB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	fp := "row-version-enrich-" + shared.NewID().String()
	f := seedRowVersionFinding(ctx, t, repo, tenantID, assetID, fp)

	analyst := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'analyst')`,
		analyst.String(), analyst.String()+"@row-version.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, analyst.String())
	})
	calls := 0
	repo.afterEnrichLoad = func(attempt int) {
		calls++
		if attempt != 0 {
			return
		}
		// Between the enrichment's read and its write: an analyst pins the
		// priority and the SLA applier moves the deadline, and someone tags it.
		if _, err := db.ExecContext(ctx, `UPDATE findings SET priority_class = 'P1', priority_class_override = TRUE,
			priority_class_overridden_by = $2, priority_class_overridden_at = NOW(),
			sla_deadline = NOW() + INTERVAL '3 days', tags = ARRAY['by-analyst'] WHERE id = $1`,
			f.ID().String(), analyst.String()); err != nil {
			t.Errorf("concurrent writer: %v", err)
		}
	}

	sighting, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceVA, "probe-tool",
		vulnerability.SeverityCritical, "updated message")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	sighting.SetFingerprint(fp)
	sighting.SetTags([]string{"from-scan"})
	if _, err := repo.EnrichBatchByFingerprints(ctx, tenantID, []*vulnerability.Finding{sighting}, "scan-row-version"); err != nil {
		t.Fatalf("enrich: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, f.ID())
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.PriorityClassOverride() || got.PriorityClass() == nil || string(*got.PriorityClass()) != "P1" {
		t.Errorf("enrichment reverted the analyst's priority override: override=%v class=%v",
			got.PriorityClassOverride(), got.PriorityClass())
	}
	if got.SLADeadline() == nil {
		t.Errorf("enrichment reverted the SLA deadline")
	}
	if !slices.Contains(got.Tags(), "by-analyst") || !slices.Contains(got.Tags(), "from-scan") {
		t.Errorf("tags = %v, want both the concurrent tag and the scan's tag", got.Tags())
	}
	if got.Severity() != vulnerability.SeverityCritical {
		t.Errorf("severity = %q, want the sighting's critical", got.Severity())
	}
	if calls < 2 {
		t.Errorf("the lost row was not read again (reads: %d)", calls)
	}
}
