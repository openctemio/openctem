package postgres

import (
	"context"
	"testing"
	"time"

	vulneventapp "github.com/openctemio/openctem/api/internal/app/vulnevent"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The vulnerability event log (RFC-117): the first run records the corpus
// and reports nothing; a new CVE with ranges, widened ranges, a severity
// rise, a rejection, a KEV addition and an EPSS crossing each report one
// event; non-material edits and replays report nothing; the tables hold no
// tenant column. Requires DATABASE_URL.
func TestVulnEventLog_DB(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	reset := `DELETE FROM vuln_events; DELETE FROM vuln_event_state; DELETE FROM vuln_event_cursors;
		DELETE FROM vulnerability_affected WHERE cve_id LIKE 'CVE-2099-%'; DELETE FROM cve_records WHERE cve_id LIKE 'CVE-2099-%';
		DELETE FROM kev_catalog WHERE cve_id LIKE 'CVE-2099-%'; DELETE FROM epss_scores WHERE cve_id LIKE 'CVE-2099-%'`
	if _, err := db.Exec(reset); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(reset) })

	for _, tbl := range []string{"vuln_events", "vuln_event_state", "vuln_event_cursors"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = $1 AND column_name LIKE '%tenant%'`, tbl).
			Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s has tenant columns: %d %v", tbl, n, err)
		}
	}

	corpus := NewCVECorpusRepository(pdb)
	em := vulneventapp.NewEmitter(NewVulnEventRepository(pdb), logger.NewNop())
	now := time.Now().UTC()
	recent := now.Add(-48 * time.Hour)
	old := now.Add(-400 * 24 * time.Hour)
	score := func(f float64) *float64 { return &f }
	rng := func(id, product, end string) cvecorpus.Range {
		return cvecorpus.Range{Product: vulnmatch.CPE{Part: "a", Vendor: "acme-evt", Product: product},
			Range: vulnmatch.Range{VulnID: id, Scheme: vulnmatch.SchemeSemver, End: end}}
	}
	apply := func(cves ...cvecorpus.CVE) {
		t.Helper()
		if _, err := corpus.ApplyPage(ctx, cves); err != nil {
			t.Fatal(err)
		}
	}
	events := func() map[string][]string {
		t.Helper()
		rows, err := db.Query(`SELECT vuln_id, kind FROM vuln_events ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][]string{}
		for rows.Next() {
			var v, k string
			if err := rows.Scan(&v, &k); err != nil {
				t.Fatal(err)
			}
			out[v] = append(out[v], k)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Existing corpus: the first run is a baseline, no events.
	apply(cvecorpus.CVE{ID: "CVE-2099-0001", Status: "Analyzed", Published: &old, Severity: "medium", CVSSScore: score(5.0),
		Ranges: []cvecorpus.Range{rng("CVE-2099-0001", "widget", "1.2.0")}})
	if _, err := db.Exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added) VALUES ('CVE-2099-0001', 'x', current_date)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []func(context.Context) (int, error){em.EmitCorpus, em.EmitKEV, em.EmitEPSS} {
		if n, err := f(ctx); err != nil || n != 0 {
			t.Fatalf("baseline emitted %d events (%v)", n, err)
		}
	}
	if got := events(); len(got) != 0 {
		t.Fatalf("baseline wrote events: %v", got)
	}

	// New CVE with ranges, a CVE without ranges, a non-material edit and an
	// old CVE that gets its first ranges.
	time.Sleep(10 * time.Millisecond)
	apply(
		cvecorpus.CVE{ID: "CVE-2099-0002", Status: "Analyzed", Published: &recent, Severity: "critical", CVSSScore: score(9.8),
			Ranges: []cvecorpus.Range{rng("CVE-2099-0002", "gadget", "2.0.0")}},
		cvecorpus.CVE{ID: "CVE-2099-0003", Status: "Received", Published: &recent},
		cvecorpus.CVE{ID: "CVE-2099-0001", Status: "Analyzed", Published: &old, Severity: "medium", CVSSScore: score(5.5),
			Description: "edited", Ranges: []cvecorpus.Range{rng("CVE-2099-0001", "widget", "1.2.0")}},
	)
	if _, err := em.EmitCorpus(ctx); err != nil {
		t.Fatal(err)
	}
	got := events()
	if len(got["CVE-2099-0002"]) != 1 || got["CVE-2099-0002"][0] != "published" {
		t.Fatalf("new CVE with ranges: %v", got)
	}
	if len(got["CVE-2099-0001"]) != 0 || len(got["CVE-2099-0003"]) != 0 {
		t.Fatalf("non-material change or CVE without ranges emitted: %v", got)
	}

	// Replay: nothing new.
	if n, err := em.EmitCorpus(ctx); err != nil || n != 0 {
		t.Fatalf("replay emitted %d (%v)", n, err)
	}

	// Widened (a new product), severity up, rejected.
	time.Sleep(10 * time.Millisecond)
	apply(
		cvecorpus.CVE{ID: "CVE-2099-0001", Status: "Analyzed", Published: &old, Severity: "high", CVSSScore: score(7.5),
			Ranges: []cvecorpus.Range{rng("CVE-2099-0001", "widget", "1.2.0"), rng("CVE-2099-0001", "widget-pro", "3.0.0")}},
		cvecorpus.CVE{ID: "CVE-2099-0002", Status: "Rejected", Rejected: true, Published: &recent},
	)
	if _, err := em.EmitCorpus(ctx); err != nil {
		t.Fatal(err)
	}
	got = events()
	if want := []string{"ranges_widened", "severity_up"}; len(got["CVE-2099-0001"]) != 2 || got["CVE-2099-0001"][0] != want[0] || got["CVE-2099-0001"][1] != want[1] {
		t.Fatalf("widened + severity: %v", got["CVE-2099-0001"])
	}
	if k := got["CVE-2099-0002"]; len(k) != 2 || k[1] != "rejected" {
		t.Fatalf("rejected: %v", k)
	}

	// KEV addition with the ransomware flag; replay adds nothing; a removal
	// is recorded silently.
	if _, err := db.Exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use)
		VALUES ('CVE-2099-0004', 'y', current_date, 'Known')`); err != nil {
		t.Fatal(err)
	}
	if n, err := em.EmitKEV(ctx); err != nil || n != 1 {
		t.Fatalf("kev added: %d %v", n, err)
	}
	var ransomware bool
	if err := db.QueryRow(`SELECT (detail->>'ransomware')::bool FROM vuln_events WHERE vuln_id = 'CVE-2099-0004' AND kind = 'kev_added'`).
		Scan(&ransomware); err != nil || !ransomware {
		t.Fatalf("kev detail: %v %v", ransomware, err)
	}
	if n, err := em.EmitKEV(ctx); err != nil || n != 0 {
		t.Fatalf("kev replay: %d %v", n, err)
	}
	if _, err := db.Exec(`DELETE FROM kev_catalog WHERE cve_id = 'CVE-2099-0001'`); err != nil {
		t.Fatal(err)
	}
	if n, err := em.EmitKEV(ctx); err != nil || n != 0 {
		t.Fatalf("kev removal: %d %v", n, err)
	}
	var inKEV bool
	if err := db.QueryRow(`SELECT in_kev FROM vuln_event_state WHERE vuln_id = 'CVE-2099-0001'`).Scan(&inKEV); err != nil || inKEV {
		t.Fatalf("kev removal not recorded: %v %v", inKEV, err)
	}

	// EPSS: a crossing upward is an event, noise below a band and a fall
	// are not.
	if _, err := db.Exec(`INSERT INTO epss_scores (cve_id, epss_score) VALUES
		('CVE-2099-0001', 0.62), ('CVE-2099-0003', 0.04)`); err != nil {
		t.Fatal(err)
	}
	if n, err := em.EmitEPSS(ctx); err != nil || n != 1 {
		t.Fatalf("epss crossing: %d %v", n, err)
	}
	if _, err := db.Exec(`UPDATE epss_scores SET epss_score = 0.2 WHERE cve_id = 'CVE-2099-0001'`); err != nil {
		t.Fatal(err)
	}
	if n, err := em.EmitEPSS(ctx); err != nil || n != 0 {
		t.Fatalf("epss fall emitted: %d %v", n, err)
	}

	// Retention.
	if _, err := db.Exec(`UPDATE vuln_events SET at = now() - interval '3 years' WHERE vuln_id = 'CVE-2099-0004'`); err != nil {
		t.Fatal(err)
	}
	if n, err := em.Prune(ctx); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
}
