package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func (f *coverageFixture) user(t *testing.T) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'closure reviewer')`, id, "cr-"+id.String()+"@it.test")
	t.Cleanup(func() { _, _ = f.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func (f *coverageFixture) propose(t *testing.T, repo *FindingRepository, ids ...shared.ID) map[shared.ID]shared.ID {
	t.Helper()
	recs := make([]vulnerability.ClosureProposalRecord, len(ids))
	for i, id := range ids {
		recs[i] = vulnerability.ClosureProposalRecord{FindingID: id, Method: vulnerability.ClosureMethodCoveredScan,
			CommandID: shared.NewID(), Evidence: map[string]any{"tool": "nuclei"}}
	}
	if _, err := repo.RecordClosureProposals(context.Background(), f.tenant, recs); err != nil {
		t.Fatalf("record: %v", err)
	}
	out := map[shared.ID]shared.ID{}
	rows, err := f.db.QueryContext(context.Background(),
		`SELECT finding_id::text, id::text FROM finding_closure_proposals WHERE tenant_id = $1 AND state = 'pending'`, f.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var fid, pid string
		if err := rows.Scan(&fid, &pid); err != nil {
			t.Fatal(err)
		}
		a, _ := shared.IDFromString(fid)
		b, _ := shared.IDFromString(pid)
		out[a] = b
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *coverageFixture) proposalState(t *testing.T, id shared.ID) (state, reason string) {
	t.Helper()
	if err := f.db.QueryRowContext(context.Background(), `SELECT state, reason FROM finding_closure_proposals WHERE id = $1`, id.String()).Scan(&state, &reason); err != nil {
		t.Fatalf("proposal state: %v", err)
	}
	return state, reason
}

// Recording is one pending row per finding (a second look refreshes it),
// only for open findings; the list and count are tenant- and scope-bound;
// a sighting after the evidence makes it ineligible and the sweep cancels it.
func TestClosureProposals_RecordListCancel_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	ctx := context.Background()
	page := pagination.New(1, 50)

	a := f.finding(t, f.host, "nuclei", "", nil)
	b := f.finding(t, f.otherHost, "nuclei", "", nil)
	closed := f.finding(t, f.host, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET status = 'false_positive' WHERE id = $1`, closed)
	foreign := other.finding(t, other.host, "nuclei", "", nil)

	// Another tenant's finding id is never proposed under this tenant.
	props := f.propose(t, repo, a, b, closed, foreign)
	if len(props) != 2 || props[a].IsZero() || props[b].IsZero() {
		t.Fatalf("proposals = %v, want a and b only", props)
	}
	// Proposed again: still one pending row each.
	if again := f.propose(t, repo, a); len(again) != 2 || again[a] != props[a] {
		t.Fatalf("re-proposal = %v, want the same pending row", again)
	}

	list, err := repo.ListClosureProposals(ctx, f.tenant, nil, page)
	if err != nil || list.Total != 2 {
		t.Fatalf("list = %+v, %v; want 2", list, err)
	}
	if n, err := other.repoCount(t); err != nil || n != 0 {
		t.Fatalf("other tenant count = %d, %v; want 0", n, err)
	}

	// A restricted member with no scope row sees nothing; one with b's
	// asset in scope sees only b.
	member := f.user(t)
	restricted := &shared.DataScope{TenantID: f.tenant, UserID: member}
	if n, err := repo.CountClosureProposals(ctx, f.tenant, restricted); err != nil || n != 0 {
		t.Fatalf("restricted count = %d, %v; want 0", n, err)
	}
	f.exec(t, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, member, f.tenant, f.otherHost)
	scoped, err := repo.ListClosureProposals(ctx, f.tenant, restricted, page)
	if err != nil || scoped.Total != 1 || scoped.Data[0].FindingID != b {
		t.Fatalf("scoped list = %+v, %v; want only b", scoped, err)
	}
	if scoped.Data[0].Tier != vulnerability.RiskTierHigh || scoped.Data[0].Evidence["tool"] != "nuclei" {
		t.Fatalf("item = %+v", scoped.Data[0])
	}

	// a is seen again after the evidence: no longer listed, the sweep
	// cancels it as seen_again.
	f.exec(t, `UPDATE findings SET last_seen_at = NOW() + interval '1 minute' WHERE id = $1`, a)
	if n, _ := repo.CountClosureProposals(ctx, f.tenant, nil); n != 1 {
		t.Fatalf("count after sighting = %d, want 1", n)
	}
	// The other tenant's sweep touches nothing here.
	if n, err := NewFindingRepository(&DB{DB: f.db}).CancelStaleClosureProposals(ctx, other.tenant); err != nil || n != 0 {
		t.Fatalf("other tenant sweep = %d, %v", n, err)
	}
	if n, err := repo.CancelStaleClosureProposals(ctx, f.tenant); err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v; want 1", n, err)
	}
	if st, why := f.proposalState(t, props[a]); st != "canceled" || why != "seen_again" {
		t.Fatalf("a = %s/%s, want canceled/seen_again", st, why)
	}
}

// evidence_at is the observation time the caller passes, so a sighting
// ingested between the scan's end and the write cancels the proposal.
func TestClosureProposals_EvidenceAtIsObservationTime_DB(t *testing.T) {
	f := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	ctx := context.Background()
	a := f.finding(t, f.host, "nuclei", "", nil)
	observed := time.Now().UTC().Add(-time.Hour)
	// seen after the scan ended, before the proposal is written
	f.exec(t, `UPDATE findings SET last_seen_at = $2 WHERE id = $1`, a, observed.Add(30*time.Minute))
	_, err := repo.RecordClosureProposals(ctx, f.tenant, []vulnerability.ClosureProposalRecord{{
		FindingID: a, Method: vulnerability.ClosureMethodCoveredScan, CommandID: shared.NewID(),
		Evidence: map[string]any{"tool": "nuclei"}, EvidenceAt: observed}})
	if err != nil {
		t.Fatal(err)
	}
	var got time.Time
	if err := f.db.QueryRowContext(ctx, `SELECT evidence_at FROM finding_closure_proposals WHERE tenant_id = $1 AND finding_id = $2`,
		f.tenant.String(), a.String()).Scan(&got); err != nil || got.Sub(observed).Abs() > time.Second {
		t.Fatalf("evidence_at = %v (%v), want %v", got, err, observed)
	}
	if n, _ := repo.CountClosureProposals(ctx, f.tenant, nil); n != 0 {
		t.Fatalf("a proposal older than a later sighting must not be listed, got %d", n)
	}
	if n, err := repo.CancelStaleClosureProposals(ctx, f.tenant); err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v; want 1", n, err)
	}
}

func (f *coverageFixture) repoCount(t *testing.T) (int, error) {
	t.Helper()
	return NewFindingRepository(&DB{DB: f.db}).CountClosureProposals(context.Background(), f.tenant, nil)
}

// Confirm closes the finding as fixed by the person, verified by the covered
// scan, with its timeline entry, only within the caller's tenant and scope
// and only while eligible; dismiss keeps the finding open with the reason.
func TestClosureProposals_ConfirmDismiss_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	ctx := context.Background()
	reviewer := f.user(t)

	ok := f.finding(t, f.host, "nuclei", "", nil)
	seen := f.finding(t, f.host, "nuclei", "", nil)
	keep := f.finding(t, f.host, "nuclei", "", nil)
	hidden := f.finding(t, f.otherHost, "nuclei", "", nil)
	props := f.propose(t, repo, ok, seen, keep, hidden)
	f.exec(t, `UPDATE findings SET last_seen_at = NOW() + interval '1 minute' WHERE id = $1`, seen)

	// Another tenant cannot decide this tenant's proposals.
	cross, err := repo.ConfirmClosureProposals(ctx, other.tenant, nil, []shared.ID{props[ok]}, reviewer, "x", "")
	if err != nil || len(cross.Applied) != 0 || cross.Skipped[props[ok]] != "not_found" {
		t.Fatalf("cross-tenant confirm = %+v, %v", cross, err)
	}
	// A restricted member cannot decide one outside their scope.
	member := f.user(t)
	f.exec(t, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, member, f.tenant, f.host)
	restricted := &shared.DataScope{TenantID: f.tenant, UserID: member}
	res, err := repo.ConfirmClosureProposals(ctx, f.tenant, restricted, []shared.ID{props[ok], props[seen], props[hidden]}, reviewer, "Lan", "checked")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 1 || res.Applied[0] != props[ok] || len(res.Findings) != 1 || res.Findings[0] != ok {
		t.Fatalf("confirm = %+v, want only ok", res)
	}
	if res.Skipped[props[seen]] != "not_eligible" || res.Skipped[props[hidden]] != "not_found" {
		t.Fatalf("skipped = %v", res.Skipped)
	}
	var status, verification, closure string
	var resolvedBy *string
	if err := f.db.QueryRowContext(ctx, `SELECT status, verification, closure_reason, resolved_by::text FROM findings WHERE id = $1`, ok.String()).
		Scan(&status, &verification, &closure, &resolvedBy); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" || verification != "covered_scan" || closure != "fixed" || resolvedBy == nil || *resolvedBy != reviewer.String() {
		t.Fatalf("finding = %s/%s/%s by %v", status, verification, closure, resolvedBy)
	}
	var entries int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND changes->>'reason' = 'closure_proposal_confirmed' AND actor_id = $3`, f.tenant.String(), ok.String(), reviewer.String()).Scan(&entries); err != nil || entries != 1 {
		t.Fatalf("timeline entries = %d, %v; want 1", entries, err)
	}
	if st, _ := f.proposalState(t, props[ok]); st != "confirmed" {
		t.Fatalf("proposal = %s", st)
	}
	if f.status(t, seen) != "new" {
		t.Fatal("a finding seen after the evidence was closed")
	}

	// Dismiss: the finding stays open, the reason is stored.
	dis, err := repo.DismissClosureProposals(ctx, f.tenant, nil, []shared.ID{props[keep]}, reviewer, vulnerability.ClosureDismissScanNotTrustworthy, "")
	if err != nil || len(dis.Applied) != 1 {
		t.Fatalf("dismiss = %+v, %v", dis, err)
	}
	if st, why := f.proposalState(t, props[keep]); st != "dismissed" || why != "scan_not_trustworthy" || f.status(t, keep) != "new" {
		t.Fatalf("dismissed = %s/%s, finding %s", st, why, f.status(t, keep))
	}
	// A decided proposal is not decided twice.
	again, _ := repo.ConfirmClosureProposals(ctx, f.tenant, nil, []shared.ID{props[keep]}, reviewer, "x", "")
	if len(again.Applied) != 0 || again.Skipped[props[keep]] != "not_found" {
		t.Fatalf("confirm after dismiss = %+v", again)
	}
}

// Recently auto-closed lists only platform closes of the last seven days in
// the caller's tenant and scope; "Reopen: not fixed" reopens such a finding
// once, as confirmed, and nothing else.
func TestRecentlyAutoClosed_Reopen_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewFindingRepository(&DB{DB: f.db})
	ctx := context.Background()
	page := pagination.New(1, 50)
	person := f.user(t)

	auto := f.finding(t, f.host, "nuclei", "", nil)
	old := f.finding(t, f.host, "nuclei", "", nil)
	manual := f.finding(t, f.host, "nuclei", "", nil)
	if _, err := repo.ResolveCoverageStale(ctx, f.tenant, []shared.ID{auto, old}); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE findings SET resolved_at = NOW() - interval '8 days' WHERE id = $1`, old)
	f.exec(t, `UPDATE findings SET status = 'resolved', resolution = 'fixed', resolved_by = $2, resolved_at = NOW() WHERE id = $1`, manual, person)

	list, err := repo.ListRecentlyAutoClosed(ctx, f.tenant, nil, page)
	if err != nil || list.Total != 1 || list.Data[0].FindingID != auto {
		t.Fatalf("auto-closed = %+v, %v; want only auto", list, err)
	}
	if list.Data[0].Verification != "covered_scan" || list.Data[0].Evidence["reason"] != "not_found_in_full_scan" {
		t.Fatalf("item = %+v", list.Data[0])
	}
	if ol, _ := NewFindingRepository(&DB{DB: f.db}).ListRecentlyAutoClosed(ctx, other.tenant, nil, page); ol.Total != 0 {
		t.Fatal("another tenant lists this tenant's closes")
	}
	restricted := &shared.DataScope{TenantID: f.tenant, UserID: person}
	if rl, _ := repo.ListRecentlyAutoClosed(ctx, f.tenant, restricted, page); rl.Total != 0 {
		t.Fatal("a member without scope lists closes")
	}

	for _, tc := range []struct {
		name   string
		tenant shared.ID
		scope  *shared.DataScope
		id     shared.ID
	}{
		{"other tenant", other.tenant, nil, auto},
		{"out of scope", f.tenant, restricted, auto},
		{"older than seven days", f.tenant, nil, old},
		{"closed by a person", f.tenant, nil, manual},
	} {
		if ok, err := repo.ReopenAutoClosedNotFixed(ctx, tc.tenant, tc.scope, tc.id, person, "p", ""); err != nil || ok {
			t.Fatalf("%s: reopen = %v, %v; want false", tc.name, ok, err)
		}
	}
	ok, err := repo.ReopenAutoClosedNotFixed(ctx, f.tenant, nil, auto, person, "p", "still vulnerable")
	if err != nil || !ok {
		t.Fatalf("reopen = %v, %v", ok, err)
	}
	if f.status(t, auto) != "confirmed" {
		t.Fatalf("status = %s, want confirmed", f.status(t, auto))
	}
	if again, _ := repo.ReopenAutoClosedNotFixed(ctx, f.tenant, nil, auto, person, "p", ""); again {
		t.Fatal("reopened twice")
	}
	var regressions int
	if err := f.db.QueryRowContext(ctx, `SELECT COALESCE(regression_count, 0) FROM findings WHERE id = $1`, auto.String()).Scan(&regressions); err == nil && regressions != 0 {
		t.Fatalf("regression_count = %d, want 0 (a wrong close is not a regression)", regressions)
	}
}
