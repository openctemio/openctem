package routes

// The material-change controller on real decisions
// (api/docs/rfcs/RFC-111-approval-policy.md §6): accepted risks end when the
// finding needs a higher tier, are flagged otherwise (or end under the
// organization's end_on_any_change); one-person false positives are flagged
// (or withdrawn under revoke); a change below the EPSS threshold only moves
// the baseline; decisions without facts get a baseline first; each
// organization's policy applies to its own decisions only.

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedChange struct {
	finding    shared.ID
	action     approvalpolicy.Action
	recipients []shared.ID
}

type recordingNotifier struct {
	mu  sync.Mutex
	got []recordedChange
}

func (n *recordingNotifier) NotifyMaterialChange(_ context.Context, d vulnerability.StandingDecision, a approvalpolicy.Action, _ []approvalpolicy.Signal) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, recordedChange{d.FindingID, a, append([]shared.ID{d.RequesterID}, d.ApproverIDs...)})
}

func (n *recordingNotifier) action(findingID string) approvalpolicy.Action {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.got {
		if c.finding.String() == findingID {
			return c.action
		}
	}
	return ""
}

func (h *approvalPolicyHarness) materialController(n *recordingNotifier) *controller.ApprovalMaterialChangeController {
	return controller.NewApprovalMaterialChangeController(
		postgres.NewFindingMaterialChangeRepository(&postgres.DB{DB: h.db}), h.svc, nil, n, 0, 500, logger.NewNop())
}

func (h *approvalPolicyHarness) reconcile(c *controller.ApprovalMaterialChangeController) {
	h.t.Helper()
	if _, err := c.Reconcile(context.Background()); err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
}

func (h *approvalPolicyHarness) acceptAndApprove(org string, requester policyUser, approvers []policyUser, severity string) (findingID, approvalID string) {
	h.t.Helper()
	findingID, _ = h.findingOnAsset(org, severity)
	req := h.requestAccept(requester, findingID)
	for _, a := range approvers {
		h.approve(a, req.ID, http.StatusOK)
	}
	if findingStatusOf(h.findingApprovalHarness, findingID) != "accepted" {
		h.t.Fatalf("%s acceptance not applied", severity)
	}
	return findingID, req.ID
}

func TestMaterialChange_AcceptedRisks_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_decision_reviews WHERE tenant_id = $1`, org)
	})
	requester, a1, a2 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	n := &recordingNotifier{}
	ctl := h.materialController(n)

	// KEV added to a medium acceptance (peer → dual): it ends.
	kev, kevApproval := h.acceptAndApprove(org, requester, []policyUser{a1}, "medium")
	// EPSS rising below the threshold: nothing but a new baseline.
	small, _ := h.acceptAndApprove(org, requester, []policyUser{a1}, "medium")
	// A critical acceptance (dual) whose EPSS crosses the threshold: the tier
	// cannot rise, so it is flagged and stands.
	crit, _ := h.acceptAndApprove(org, requester, []policyUser{a1, a2}, "critical")

	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	h.exec(`UPDATE findings SET epss_score = 0.3 WHERE id = $1`, small)
	h.exec(`UPDATE findings SET epss_score = 0.9 WHERE id = $1`, crit)
	h.reconcile(ctl)

	if st := findingStatusOf(h.findingApprovalHarness, kev); st != "confirmed" {
		t.Fatalf("KEV-added acceptance: finding %s, want confirmed", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND status = 'expired'`, kevApproval); n != 1 {
		t.Fatal("ended acceptance request not expired")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'acceptance_expired'
		AND changes->>'reason' = 'material_change' AND changes->'signals' ? 'kev_added'`, kev); n != 1 {
		t.Fatal("timeline entry of the ended acceptance missing")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.material_change_ended' AND resource_id = $2`, org, kev); n != 1 {
		t.Fatal("ended acceptance not audited")
	}
	if n.action(kev) != approvalpolicy.ActionEnd {
		t.Fatalf("notification for the ended acceptance: %q", n.action(kev))
	}
	for _, c := range n.got {
		if c.finding.String() == kev && (c.recipients[0].String() != requester.id || len(c.recipients) < 2) {
			t.Fatalf("recipients of the change: %v", c.recipients)
		}
	}

	if st := findingStatusOf(h.findingApprovalHarness, small); st != "accepted" || n.action(small) != "" {
		t.Fatalf("EPSS below the threshold changed the decision: %s %q", st, n.action(small))
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE finding_id = $1 AND (facts_baseline->>'epss')::float8 = 0.3`, small); n != 1 {
		t.Fatal("baseline not moved for a non-material change")
	}

	if st := findingStatusOf(h.findingApprovalHarness, crit); st != "accepted" {
		t.Fatalf("dual acceptance with EPSS crossing: %s, want accepted (flagged)", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1 AND reason = 'material_change_accepted' AND cleared_at IS NULL`, crit); n != 1 {
		t.Fatal("flag of the critical acceptance missing")
	}
	if n.action(crit) != approvalpolicy.ActionFlag {
		t.Fatalf("notification of the flag: %q", n.action(crit))
	}

	// A second run does nothing more (no duplicate flag, no repeat work).
	before := len(n.got)
	h.reconcile(ctl)
	if len(n.got) != before {
		t.Fatalf("a second run acted again: %d → %d", before, len(n.got))
	}

	// end_on_any_change: the next material change ends even a dual decision.
	setFPLevel(h.findingApprovalHarness, org, `{"policy":{"on_material_change":{"accepted":"end_on_any_change"}}}`)
	h.exec(`UPDATE findings SET validation_outcome = 'reproducible' WHERE id = $1`, crit)
	h.reconcile(ctl)
	if st := findingStatusOf(h.findingApprovalHarness, crit); st != "confirmed" {
		t.Fatalf("end_on_any_change: %s", st)
	}
}

func TestMaterialChange_SinglePersonFalsePositives_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	t.Cleanup(func() {
		for _, id := range []string{org, other} {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_decision_reviews WHERE tenant_id = $1`, id)
		}
	})
	admin, otherAdmin := h.member(org, "admin"), h.member(other, "admin")
	n := &recordingNotifier{}
	ctl := h.materialController(n)
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off","policy":{"on_material_change":{"single_person_fp":"revoke"}}}`)
	setFPLevel(h.findingApprovalHarness, other, `{"fp_approval":"off"}`)

	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(other, "low")
	for _, c := range []struct {
		u policyUser
		f string
	}{{admin, f1}, {otherAdmin, f2}} {
		if status, single, _ := requestFP(h.findingApprovalHarness, c.u, c.f); status != "approved" || !single {
			t.Fatalf("single-person false positive: %s %v", status, single)
		}
	}
	h.exec(`UPDATE findings SET validation_outcome = 'reproducible' WHERE id = ANY($1::uuid[])`, "{"+f1+","+f2+"}")
	h.reconcile(ctl)

	// The organization that chose revoke: withdrawn, on the timeline (transition), audited.
	if st := findingStatusOf(h.findingApprovalHarness, f1); st != "confirmed" {
		t.Fatalf("revoke policy: %s", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'status_changed'
		AND changes->>'reason' = 'material_change'`, f1); n != 1 {
		t.Fatal("withdrawn false positive not on the timeline")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.material_change_revoked'`, org); n != 1 {
		t.Fatal("withdrawal not audited")
	}
	// The other organization keeps the floor: a flag, the decision stands.
	if st := findingStatusOf(h.findingApprovalHarness, f2); st != "false_positive" {
		t.Fatalf("flag policy: %s", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1 AND reason = 'material_change_single_person' AND cleared_at IS NULL`, f2); n != 1 {
		t.Fatal("flag missing")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'finding_approval.material_change_%'`, other); n != 1 {
		t.Fatalf("audit rows of the other organization: %d", n)
	}
}

// A decision made before decision facts existed gets today's facts as its
// baseline on the first run and nothing else.
func TestMaterialChange_LegacyDecisionGetsBaseline_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester, approver := h.member(org, "admin"), h.member(org, "admin")
	f, id := h.acceptAndApprove(org, requester, []policyUser{approver}, "low")
	h.exec(`UPDATE finding_status_approvals SET decision_facts = NULL, facts_baseline = NULL, tier = NULL WHERE id = $1`, id)
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, f)
	n := &recordingNotifier{}
	h.reconcile(h.materialController(n))
	if st := findingStatusOf(h.findingApprovalHarness, f); st != "accepted" || len(n.got) != 0 {
		t.Fatalf("legacy decision acted on at first sight: %s %d", st, len(n.got))
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND facts_baseline->>'severity' = 'critical'`, id); n != 1 {
		t.Fatal("legacy decision baseline not set")
	}
}

// A decision the controller looked at (even one that failed) goes to the back
// of the line, so the same stuck decisions do not hold the batch and starve
// other organizations.
func TestMaterialChange_LeastRecentlyCheckedFirst_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester, approver := h.member(org, "admin"), h.member(org, "admin")
	f1, id1 := h.acceptAndApprove(org, requester, []policyUser{approver}, "low")
	f2, id2 := h.acceptAndApprove(org, requester, []policyUser{approver}, "low")
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = ANY($1::uuid[])`, "{"+f1+","+f2+"}")
	repo := postgres.NewFindingMaterialChangeRepository(&postgres.DB{DB: h.db})
	ctx := context.Background()
	first := func() string {
		t.Helper()
		got, err := repo.ListStandingDecisions(ctx, 1)
		if err != nil || len(got) != 1 {
			t.Fatalf("list: %v %d", err, len(got))
		}
		return got[0].ApprovalID.String()
	}
	a := first()
	if a != id1 && a != id2 {
		t.Fatalf("unexpected decision %s", a)
	}
	got, _ := repo.ListStandingDecisions(ctx, 1)
	if err := repo.MarkChecked(ctx, got[0]); err != nil {
		t.Fatal(err)
	}
	if b := first(); b == a {
		t.Fatal("the decision just checked is listed first again; a stuck decision would hold the batch")
	}
}

// A decision made after the change was seen is not undone by it: the
// controller stops when the finding holds a newer approved request, and when
// the request it acts on is no longer approved.
func TestMaterialChange_NewerDecisionWins_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester, approver := h.member(org, "admin"), h.member(org, "admin")
	repo := postgres.NewFindingMaterialChangeRepository(&postgres.DB{DB: h.db})
	ctx := context.Background()
	now := time.Now().UTC()
	signals := []approvalpolicy.Signal{approvalpolicy.SignalKEVAdded}
	standing := func(approvalID string) vulnerability.StandingDecision {
		t.Helper()
		all, err := repo.ListStandingDecisions(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range all {
			if d.ApprovalID.String() == approvalID {
				return d
			}
		}
		t.Fatalf("decision %s is not listed", approvalID)
		return vulnerability.StandingDecision{}
	}

	// An accepted risk: a newer approved request exists, so ending it is refused.
	f, old := h.acceptAndApprove(org, requester, []policyUser{approver}, "low")
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, f)
	d := standing(old)
	h.exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by, justification, status, approved_by, approved_at, closure_reason, expires_at)
	        VALUES ($1, $2, 'accepted', $3, 'renewed', 'approved', $4, now() + interval '1 second', 'compensating_control', now() + interval '30 days')`,
		org, f, requester.id, approver.id)
	if done, err := repo.EndAcceptance(ctx, d, signals, nil, now); err != nil || done {
		t.Fatalf("ended an acceptance although a newer approved request exists: done=%v err=%v", done, err)
	}
	if st := findingStatusOf(h.findingApprovalHarness, f); st != "accepted" {
		t.Fatalf("finding is %s, want accepted", st)
	}

	// A request that is no longer approved is not acted on either.
	f2, old2 := h.acceptAndApprove(org, requester, []policyUser{approver}, "low")
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, f2)
	d2 := standing(old2)
	h.exec(`UPDATE finding_status_approvals SET status = 'expired' WHERE id = $1`, old2)
	if done, err := repo.EndAcceptance(ctx, d2, signals, nil, now); err != nil || done {
		t.Fatalf("ended an acceptance whose request is no longer approved: done=%v err=%v", done, err)
	}
	if st := findingStatusOf(h.findingApprovalHarness, f2); st != "accepted" {
		t.Fatalf("finding is %s, want accepted", st)
	}

	// A single-person false positive is not withdrawn when a newer approved
	// request exists.
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	f3, _ := h.findingOnAsset(org, "low")
	status, single, id3 := requestFP(h.findingApprovalHarness, requester, f3)
	if status != "approved" || !single {
		t.Fatalf("single-person false positive: %s %v", status, single)
	}
	h.exec(`UPDATE findings SET validation_outcome = 'reproducible' WHERE id = $1`, f3)
	d3 := standing(id3)
	h.exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by, justification, status, approved_by, approved_at, closure_reason)
	        VALUES ($1, $2, 'false_positive', $3, 'again', 'approved', $4, now() + interval '1 second', 'test_or_example_code')`,
		org, f3, requester.id, approver.id)
	if done, err := repo.RevokeFalsePositive(ctx, d3, signals, nil, now); err != nil || done {
		t.Fatalf("withdrew a false positive although a newer approved request exists: done=%v err=%v", done, err)
	}
	if st := findingStatusOf(h.findingApprovalHarness, f3); st != "false_positive" {
		t.Fatalf("finding is %s, want false_positive", st)
	}
}
