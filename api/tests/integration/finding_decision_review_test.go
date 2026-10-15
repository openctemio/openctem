package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func taintTrace(fp, sourcePath, sourceCode string) vulnerability.FindingTrace {
	flows := vulnerability.NormalizeDataFlows([]vulnerability.DataFlow{{Index: 0, Steps: []vulnerability.DataFlowStep{
		{Index: 0, LocationType: "source", Location: &vulnerability.FindingLocation{Path: sourcePath, StartLine: 3, Snippet: sourceCode}},
		{Index: 1, LocationType: "sink", Location: &vulnerability.FindingLocation{Path: "src/db.js", StartLine: 22, Snippet: "db.query(q)"}},
	}}})
	return vulnerability.FindingTrace{Fingerprint: fp, Flows: flows, Hash: vulnerability.TraceHash(flows)}
}

type reviewFixture struct {
	db            *sql.DB
	pdb           *postgres.DB
	tenant, other shared.ID
	asset         shared.ID
}

func newReviewFixture(t *testing.T) *reviewFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &reviewFixture{db: db, pdb: &postgres.DB{DB: db}, tenant: createTestTenant(t, db, "review"),
		other: createTestTenant(t, db, "review-other"), asset: shared.NewID()}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'rv-repo', 'repository')`,
		f.asset.String(), f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *reviewFixture) finding(t *testing.T, tenant, asset shared.ID, fp, status string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolution)
		VALUES ($1, $2, $3, 'sast', 'semgrep', 'm', 'high', $4, $5, 'decided by a person')`,
		id.String(), tenant.String(), asset.String(), fp, status); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *reviewFixture) state(t *testing.T, id shared.ID) (status string, openFlags, entries int) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT status,
			(SELECT COUNT(*) FROM finding_decision_reviews r WHERE r.finding_id = f.id AND r.tenant_id = f.tenant_id AND r.cleared_at IS NULL),
			(SELECT COUNT(*) FROM finding_activities a WHERE a.finding_id = f.id AND a.tenant_id = f.tenant_id AND a.activity_type = 'decision_review')
		FROM findings f WHERE f.id = $1`, id.String()).Scan(&status, &openFlags, &entries); err != nil {
		t.Fatal(err)
	}
	return
}

// A changed taint source never reverses a decision: a false positive stays a
// false positive and gets one review flag with one timeline entry (once, not
// again on the next scan). Another tenant's finding with the same key is not
// touched. A status change clears the flag.
func TestDecisionReview_TaintSourceChangeFlagsInsteadOfReopening(t *testing.T) {
	f := newReviewFixture(t)
	ctx := context.Background()
	flows := postgres.NewDataFlowRepository(f.pdb)
	const fp = "rv-taint-key"
	id := f.finding(t, f.tenant, f.asset, fp, "false_positive")
	otherAsset := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'rv-other', 'repository')`,
		otherAsset.String(), f.other.String()); err != nil {
		t.Fatal(err)
	}
	otherID := f.finding(t, f.other, otherAsset, fp, "false_positive")

	if _, err := flows.ReplaceDataFlows(ctx, f.tenant, []vulnerability.FindingTrace{taintTrace(fp, "src/api.js", "req.query.id")}); err != nil {
		t.Fatal(err)
	}
	changed := []vulnerability.FindingTrace{taintTrace(fp, "src/handler.js", "req.body.name")}
	for run := 0; run < 2; run++ {
		got, err := flows.ReviewOnTaintSourceChange(ctx, f.tenant, changed)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 && len(got) != 1 {
			t.Fatalf("flagged %d findings, want 1", len(got))
		}
		if run == 1 && len(got) != 0 {
			t.Errorf("a second scan flagged %d again, want 0 (one open flag)", len(got))
		}
	}
	if st, flags, entries := f.state(t, id); st != "false_positive" || flags != 1 || entries != 1 {
		t.Errorf("after the source change: status=%s open flags=%d entries=%d, want false_positive, 1, 1", st, flags, entries)
	}
	if st, flags, _ := f.state(t, otherID); st != "false_positive" || flags != 0 {
		t.Errorf("other tenant's finding: status=%s flags=%d, want untouched", st, flags)
	}

	// A person revisits the decision: the flag clears.
	if _, err := f.db.Exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if _, flags, _ := f.state(t, id); flags != 0 {
		t.Errorf("open flags after the status changed = %d, want 0", flags)
	}
}

// The IOC correlator path: a decided finding (false positive, accepted,
// duplicate) gets a flag; a finding that holds no decision gets none.
func TestDecisionReview_RaiseOnlyOnDecisions(t *testing.T) {
	f := newReviewFixture(t)
	ctx := context.Background()
	repo := postgres.NewFindingRepository(f.pdb)
	canonical := f.finding(t, f.tenant, f.asset, "rv-canonical", "confirmed")
	for _, st := range []string{"false_positive", "accepted", "duplicate", "resolved", "confirmed"} {
		id := f.finding(t, f.tenant, f.asset, "rv-"+st, "confirmed")
		if st == "duplicate" {
			if _, err := f.db.Exec(`UPDATE findings SET status = 'duplicate', duplicate_of = $2 WHERE id = $1`, id.String(), canonical.String()); err != nil {
				t.Fatal(err)
			}
		} else if _, err := f.db.Exec(`UPDATE findings SET status = $2 WHERE id = $1`, id.String(), st); err != nil {
			t.Fatal(err)
		}
		raised, err := repo.RaiseDecisionReview(ctx, f.tenant, id, postgres.DecisionReviewIOCMatch, map[string]any{"match": "ioc"})
		if err != nil {
			t.Fatal(err)
		}
		decided := vulnerability.IsDispositionedStatus(vulnerability.FindingStatus(st))
		if raised != decided {
			t.Errorf("%s: raised=%v, want %v", st, raised, decided)
		}
		if got, flags, _ := f.state(t, id); got != st || (flags == 1) != decided {
			t.Errorf("%s: status=%s flags=%d", st, got, flags)
		}
		// Another tenant cannot flag it.
		if raised, _ := repo.RaiseDecisionReview(ctx, f.other, id, postgres.DecisionReviewIOCMatch, nil); raised {
			t.Errorf("%s: another tenant raised a flag on it", st)
		}
	}
}
