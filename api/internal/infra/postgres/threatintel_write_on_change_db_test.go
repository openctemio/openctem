package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
)

// A daily feed moves the percentile of nearly every CVE but the score of about
// 1 %. The sync must write only the rows whose score moved, keep the
// percentile in the curve, and write nothing for an unchanged feed.
func TestEPSSUpsertBatch_WritesOnlyChangedScores(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	repo := &EPSSRepository{db: pdb}

	suffix := shared.NewID().String()[30:]
	cveA, cveB := "CVE-2099-A"+suffix, "CVE-2099-B"+suffix
	const scoreA, scoreB, scoreA2 = 0.987651, 0.987652, 0.987653
	var oldDate *time.Time
	_ = db.QueryRow(`SELECT data_date FROM threat_intel_sync_status WHERE source_name = 'epss'`).Scan(&oldDate)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM epss_scores WHERE cve_id IN ($1, $2)`, cveA, cveB)
		_, _ = db.Exec(`DELETE FROM epss_percentile_curve WHERE score IN ($1, $2, $3)`, scoreA, scoreB, scoreA2)
		_, _ = db.Exec(`UPDATE threat_intel_sync_status SET data_date = $1 WHERE source_name = 'epss'`, oldDate)
	})

	day1 := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	if err := repo.UpsertBatch(ctx, []*threatintel.EPSSScore{
		threatintel.NewEPSSScore(cveA, scoreA, 91.5, "v1", day1),
		threatintel.NewEPSSScore(cveB, scoreB, 92.5, "v1", day1),
	}); err != nil {
		t.Fatal(err)
	}

	xmin := func(cve string) string {
		t.Helper()
		var x string
		if err := db.QueryRow(`SELECT xmin::text FROM epss_scores WHERE cve_id = $1`, cve).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	a1, b1 := xmin(cveA), xmin(cveB)

	// Next day: both percentiles moved, only A's score moved.
	if err := repo.UpsertBatch(ctx, []*threatintel.EPSSScore{
		threatintel.NewEPSSScore(cveA, scoreA2, 93.5, "v1", day2),
		threatintel.NewEPSSScore(cveB, scoreB, 90.5, "v1", day2),
	}); err != nil {
		t.Fatal(err)
	}
	if xmin(cveA) == a1 {
		t.Error("a CVE whose score moved was not updated")
	}
	if xmin(cveB) != b1 {
		t.Error("a CVE whose score did not move was rewritten (only its percentile moved)")
	}
	got, err := repo.GetByCVEID(ctx, cveB)
	if err != nil {
		t.Fatal(err)
	}
	if got.Percentile() != 90.5 {
		t.Errorf("percentile = %v, want the curve's current 90.5", got.Percentile())
	}
	if !got.ScoreDate().Equal(day2) {
		t.Errorf("score date = %v, want the sync status date %v", got.ScoreDate(), day2)
	}
	top, err := repo.GetTopPercentile(ctx, 10, 100000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range top {
		if s.CVEID() == cveA && s.Percentile() == 93.5 {
			found = true
		}
	}
	if !found {
		t.Error("GetTopPercentile did not return the CVE at percentile 93.5")
	}

	// The same feed again writes no row version at all.
	a2, b2 := xmin(cveA), xmin(cveB)
	if err := repo.UpsertBatch(ctx, []*threatintel.EPSSScore{
		threatintel.NewEPSSScore(cveA, scoreA2, 93.5, "v1", day2),
		threatintel.NewEPSSScore(cveB, scoreB, 90.5, "v1", day2),
	}); err != nil {
		t.Fatal(err)
	}
	if xmin(cveA) != a2 || xmin(cveB) != b2 {
		t.Error("an unchanged feed rewrote EPSS rows")
	}
}

func TestKEVUpsertBatch_WritesOnlyChangedEntries(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	repo := &KEVRepository{db: pdb}

	suffix := shared.NewID().String()[30:]
	cveA, cveB := "CVE-2099-K"+suffix, "CVE-2099-L"+suffix
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM kev_catalog WHERE cve_id IN ($1, $2)`, cveA, cveB) })

	added := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	due := added.AddDate(0, 0, 21)
	entries := func(noteA string) []*threatintel.KEVEntry {
		return []*threatintel.KEVEntry{
			threatintel.NewKEVEntry(cveA, "vendor", "product", "name A", "desc", added, due, "Unknown", noteA, []string{"CWE-79"}),
			threatintel.NewKEVEntry(cveB, "vendor", "product", "name B", "desc", added, due, "Known", "", nil),
		}
	}
	if err := repo.UpsertBatch(ctx, entries("n1")); err != nil {
		t.Fatal(err)
	}
	xmin := func(cve string) string {
		t.Helper()
		var x string
		if err := db.QueryRow(`SELECT xmin::text FROM kev_catalog WHERE cve_id = $1`, cve).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	a1, b1 := xmin(cveA), xmin(cveB)

	if err := repo.UpsertBatch(ctx, entries("n1")); err != nil {
		t.Fatal(err)
	}
	if xmin(cveA) != a1 || xmin(cveB) != b1 {
		t.Fatal("an unchanged KEV feed rewrote rows")
	}

	if err := repo.UpsertBatch(ctx, entries("n2")); err != nil {
		t.Fatal(err)
	}
	if xmin(cveA) == a1 {
		t.Error("a changed KEV entry was not updated")
	}
	if xmin(cveB) != b1 {
		t.Error("an unchanged KEV entry was rewritten beside a changed one")
	}
	var notes string
	if err := db.QueryRow(`SELECT notes FROM kev_catalog WHERE cve_id = $1`, cveA).Scan(&notes); err != nil || notes != "n2" {
		t.Errorf("notes = %q (%v), want n2", notes, err)
	}
}
