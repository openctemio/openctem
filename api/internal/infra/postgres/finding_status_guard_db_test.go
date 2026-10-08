package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Every SQL write of findings.status follows the finding lifecycle: a row in
// a status the lifecycle does not move to the target is left alone, and the
// write stays inside its tenant.

func (f *coverageFixture) findingIn(t *testing.T, status string) shared.ID {
	t.Helper()
	id := f.finding(t, f.host, "nuclei", f.scan.String(), nil)
	f.exec(t, `UPDATE findings SET status = $2 WHERE id = $1`, id, status)
	return id
}

func TestFindingStatusGuard_UpdateStatusBatch_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	fixApplied := f.findingIn(t, "fix_applied")
	inProgress := f.findingIn(t, "in_progress")
	newOne := f.findingIn(t, "new")
	falsePositive := f.findingIn(t, "false_positive")

	// Resolve: only fix_applied may be resolved by a person; in_progress and
	// new may not, a false positive may not.
	if err := repo.UpdateStatusBatch(ctx, f.tenant, []shared.ID{fixApplied, inProgress, newOne, falsePositive},
		vulnerability.FindingStatusResolved, "fixed", nil, vulnerability.ResolutionMethodSecurityReviewed); err != nil {
		t.Fatal(err)
	}
	want := map[shared.ID]string{fixApplied: "resolved", inProgress: "in_progress", newOne: "new", falsePositive: "false_positive"}
	for id, w := range want {
		if got := f.status(t, id); got != w {
			t.Errorf("finding %s = %s, want %s", id, got, w)
		}
	}

	// The same call under another tenant changes nothing.
	other := f.findingIn(t, "fix_applied")
	if err := repo.UpdateStatusBatch(ctx, shared.NewID(), []shared.ID{other},
		vulnerability.FindingStatusResolved, "x", nil, vulnerability.ResolutionMethodSecurityReviewed); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, other); got != "fix_applied" {
		t.Errorf("a write under another tenant moved the finding to %s", got)
	}
}

func TestFindingStatusGuard_BulkUpdateStatusByFilter_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	fixApplied := f.findingIn(t, "fix_applied")
	inProgress := f.findingIn(t, "in_progress")

	filter := vulnerability.FindingFilter{Statuses: []vulnerability.FindingStatus{
		vulnerability.FindingStatusFixApplied, vulnerability.FindingStatusInProgress,
	}}
	n, err := repo.BulkUpdateStatusByFilter(ctx, f.tenant, filter, vulnerability.FindingStatusResolved,
		"verified", nil, vulnerability.ResolutionMethodSecurityReviewed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || f.status(t, fixApplied) != "resolved" || f.status(t, inProgress) != "in_progress" {
		t.Fatalf("moved %d; fix_applied -> %s, in_progress -> %s", n, f.status(t, fixApplied), f.status(t, inProgress))
	}
}

// A scan with coverage resolves open work only, never a finding handed to
// validation or a stale one (those have their own rules).
func TestFindingStatusGuard_CoverageResolveFromStates_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	ids := map[string]shared.ID{}
	for _, s := range []string{"new", "confirmed", "in_progress", "fix_applied", "validated_fixed", "not_observed", "accepted", "false_positive"} {
		ids[s] = f.findingIn(t, s)
	}
	all := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		all = append(all, id)
	}
	if _, err := repo.ResolveCoverageStale(ctx, f.tenant, all); err != nil {
		t.Fatal(err)
	}
	for s, id := range ids {
		want := s
		if s == "new" || s == "confirmed" || s == "in_progress" || s == "fix_applied" {
			want = "resolved"
		}
		if got := f.status(t, id); got != want {
			t.Errorf("%s finding -> %s, want %s", s, got, want)
		}
	}
}

// A retest decision that is not a lifecycle move is refused and nothing is
// written: the finding keeps its status and the retest stays pending.
func TestFindingStatusGuard_RetestSettleRefusesIllegalMove_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRetestRepository(&DB{DB: f.db})

	fp := f.findingIn(t, "false_positive")
	retestID := shared.NewID()
	f.exec(t, `INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, prior_status, template_id, target, deadline_at)
		VALUES ($1, $2, $3, 'manual', 'false_positive', 'tpl', 'https://example.com', $4)`,
		retestID, f.tenant, fp, time.Now().Add(time.Hour))

	_, err := repo.Settle(ctx, retest.SettleInput{
		TenantID: f.tenant, RetestID: retestID, FindingID: fp, Outcome: retest.OutcomeConfirmedFixed,
		TemplateID: "tpl",
		Decide: func(vulnerability.FindingStatus) retest.SettleDecision {
			return retest.SettleDecision{Next: vulnerability.FindingStatusResolved, Change: true}
		},
	})
	if err == nil {
		t.Fatal("settle moved a false positive to resolved")
	}
	if got := f.status(t, fp); got != "false_positive" {
		t.Fatalf("finding = %s", got)
	}
	var st string
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM finding_retests WHERE id = $1`, retestID.String()).Scan(&st); err != nil || st != "pending" {
		t.Fatalf("retest = %s, %v", st, err)
	}
}
