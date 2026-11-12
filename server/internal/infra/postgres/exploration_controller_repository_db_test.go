package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Every read the controller makes is bound to the tenant: another tenant's
// subject, run and findings are not seen; outcomes count only the tenant's
// own verdicts.
func TestExplorationControllerStore_TenantBound_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	store := NewExplorationControllerRepository(&DB{DB: f.db})
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()

	subj, err := store.Subjects(ctx, f.tenant, []shared.ID{f.host, other.host})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := subj[f.host]; !ok || len(subj) != 1 {
		t.Fatalf("subjects = %v, want only the tenant's asset", subj)
	}

	run := shared.NewID()
	f.exec(t, `INSERT INTO scan_runs (id, tenant_id, scan_id, status, trigger_type, kind) VALUES ($1, $2, $3, 'completed', 'system', 'system')`, run, f.tenant, f.scan)
	theirRun := shared.NewID()
	other.exec(t, `INSERT INTO scan_runs (id, tenant_id, scan_id, status, trigger_type, kind) VALUES ($1, $2, $3, 'completed', 'system', 'system')`, theirRun, other.tenant, other.scan)
	runs, err := store.Runs(ctx, f.tenant, []shared.ID{run, theirRun})
	if err != nil || len(runs) != 1 || runs[run].Status != "completed" {
		t.Fatalf("runs = %v (%v)", runs, err)
	}

	// A finding the run reported on the subject is its yield.
	fid := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `INSERT INTO finding_sightings (tenant_id, finding_id, channel, sender, tool, first_seen_at, last_seen_at, last_run_id)
		VALUES ($1, $2, 'scan', '', 'nuclei', now(), now(), $3)`, f.tenant, fid, run)
	ys, err := store.RunFindings(ctx, f.tenant, run, f.host)
	if err != nil || len(ys) != 1 || ys[0].ID != fid {
		t.Fatalf("yields = %v (%v)", ys, err)
	}
	if ys, _ := store.RunFindings(ctx, other.tenant, run, f.host); len(ys) != 0 {
		t.Fatal("another tenant read this tenant's run findings")
	}

	// Outcomes per cell come from this tenant's verdicts only.
	l, _ := leadOn(t, repo, f, f.host)
	if err := repo.AddVerdict(ctx, exploration.Verdict{TenantID: f.tenant, LeadID: l.ID, Verdict: exploration.VerdictProven,
		Tier: exploration.TierDeterministic, Checker: "scan_run"}); err != nil {
		t.Fatal(err)
	}
	cells, err := store.Cells(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	c := cells[exploration.CellKey("dns.takeover_check", "check.takeover")]
	if c.Tried != 1 || c.Useful != 1 {
		t.Fatalf("cell = %+v", c)
	}
	if cells, _ := store.Cells(ctx, other.tenant); len(cells) != 0 {
		t.Fatal("another tenant sees this tenant's outcomes")
	}

	// Match state: a likely finding is confirmed, a closed one closed.
	f.exec(t, `UPDATE findings SET tool_name = 'version-match', confidence = 95 WHERE id = $1`, fid)
	m, err := store.MatchState(ctx, f.tenant, []shared.ID{fid})
	if err != nil || m.Total != 1 || m.Confirmed != 1 {
		t.Fatalf("match = %+v (%v)", m, err)
	}
	if m, _ := store.MatchState(ctx, other.tenant, []shared.ID{fid}); m.Total != 0 {
		t.Fatal("another tenant read this tenant's findings")
	}
}
