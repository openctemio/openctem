package routes

// Review of the risk acceptance level's guards: raising a level puts the
// standing decisions one person made under review, the sole member's own
// approval is checked again when it is written, a delegated credential never
// decides alone, and the notice of a settings change names every lowering
// (api/docs/architecture/finding-status-lifecycle.md, "Approval levels").

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// openReview counts the open level_raised review flags on a finding.
func openReview(h *findingApprovalHarness, findingID string) int {
	h.t.Helper()
	return h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1
		AND reason = 'material_change_single_person' AND cleared_at IS NULL AND evidence->>'change' = 'level_raised'`, findingID)
}

// Raising the risk acceptance level puts the standing acceptances one person
// made under review when the new level gives them to a second person: from
// off to high_and_above the material ones only, to all every one of them.
// The decisions stand (the finding stays accepted), each flag has a timeline
// entry, a pending request is not touched, and another organization's
// decisions are never flagged.
func TestFindingAcceptPolicy_RaisingFlagsDecisionsMadeAlone_DB(t *testing.T) {
	h := newAcceptPolicyHarness(t, nil)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	otherAdmin := h.member(other, "admin")
	otherOwner := h.member(other, "owner")
	setFPLevel(h, org, `{"accept_approval":"off"}`)
	setFPLevel(h, other, `{"accept_approval":"off"}`)

	critical, low := h.newFinding(org, "critical"), h.newFinding(org, "low")
	for _, f := range []string{critical, low} {
		if r := requestAcceptance(h, admin, f); !r.SinglePerson {
			t.Fatalf("setup: not decided alone: %+v", r)
		}
	}
	foreign := h.newFinding(other, "critical")
	if r := requestAcceptance(h, otherAdmin, foreign); !r.SinglePerson {
		t.Fatalf("setup: not decided alone in the other organization: %+v", r)
	}

	const url = "/api/v1/organization/settings/finding-approvals/"
	h.expect(owner, http.MethodPatch, url, `{"accept_approval":"high_and_above"}`, http.StatusOK)
	if openReview(h, critical) != 1 {
		t.Fatal("raising to high_and_above did not put the critical acceptance made alone under review")
	}
	if openReview(h, low) != 0 {
		t.Fatal("raising to high_and_above flagged an acceptance that level still lets one person make")
	}

	h.expect(owner, http.MethodPatch, url, `{"accept_approval":"all"}`, http.StatusOK)
	if openReview(h, low) != 1 || openReview(h, critical) != 1 {
		t.Fatal("raising to all did not put every acceptance made alone under review exactly once")
	}
	for _, f := range []string{critical, low} {
		if s := findingStatusOf(h, f); s != "accepted" {
			t.Fatalf("a raised level undid a decision: %s", s)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'decision_review'
		AND changes->'evidence'->>'change' = 'level_raised'`, org); n != 2 {
		t.Fatalf("timeline entries for the raised level: %d, want 2", n)
	}
	if openReview(h, foreign) != 0 {
		t.Fatal("raising one organization's level flagged another organization's decision")
	}
	// The other organization raising its own level flags its own decision.
	h.expect(otherOwner, http.MethodPatch, url, `{"accept_approval":"all"}`, http.StatusOK)
	if openReview(h, foreign) != 1 {
		t.Fatal("the other organization's raise did not flag its decision")
	}
}

// The sole member's own approval is checked again when it is written: a
// member who became active after the service's check, or a risk acceptance
// level raised to all since, refuses it in the same transaction.
func TestFindingApprovals_SoloRecheckedAtWrite_DB(t *testing.T) {
	var repo *postgres.FindingApprovalRepository
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		svc.SetSoloApproval(postgres.NewScopeActorRepository(db), nil, ts)
		vh.SetFindingApprovalSettings(ts)
		repo = postgres.NewFindingApprovalRepository(db)
	})
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	tid, _ := shared.IDFromString(org)
	uid, _ := shared.IDFromString(owner.id)
	ctx := context.Background()

	selfApprove := func(approvalID string, acceptAlone bool) error {
		t.Helper()
		aid, _ := shared.IDFromString(approvalID)
		a, err := repo.GetByTenantAndID(ctx, tid, aid)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.SelfApprove(uid, "one-person company; reviewed it myself", acceptAlone); err != nil {
			t.Fatal(err)
		}
		entry, err := vulnerability.NewFindingActivity(tid, a.FindingID, vulnerability.ActivityApprovalApproved,
			&uid, vulnerability.ActorTypeUser, map[string]any{"approval_id": approvalID, "self_approved": true}, vulnerability.SourceAPI, nil)
		if err != nil {
			t.Fatal(err)
		}
		return repo.ApproveAndApply(ctx, a, entry)
	}

	// A member active at the moment of writing.
	fp := h.newFinding(org, "medium")
	fpReq := h.requestStatus(owner, fp, "false_positive")
	second := h.member(org, "member")
	if err := selfApprove(fpReq, false); !errors.Is(err, vulnerability.ErrSoloApprovalNotAllowed) {
		t.Fatalf("self-approval written with another active member: %v", err)
	}
	if s := findingStatusOf(h, fp); s != "confirmed" {
		t.Fatalf("the refused self-approval changed the finding: %s", s)
	}
	h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, second.id, org)

	// The risk acceptance level raised to all after the service's check.
	setFPLevel(h, org, `{"accept_approval":"high_and_above"}`)
	acc := h.newFinding(org, "critical")
	end := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	accReq := decodeID(t, h.expect(owner, http.MethodPost, "/api/v1/findings/"+acc+"/approvals/",
		`{"requested_status":"accepted","closure_reason":"no_fix_available","justification":"vendor patch next quarter","expires_at":"`+end+`"}`,
		http.StatusCreated))
	setFPLevel(h, org, `{"accept_approval":"all"}`)
	if err := selfApprove(accReq, true); !errors.Is(err, vulnerability.ErrSoloApprovalFalsePositiveOnly) {
		t.Fatalf("self-approved acceptance written under all: %v", err)
	}
	if s := findingStatusOf(h, acc); s != "confirmed" {
		t.Fatalf("the refused acceptance changed the finding: %s", s)
	}

	// Still the sole member, under a level that allows it: written.
	setFPLevel(h, org, `{"accept_approval":"high_and_above"}`)
	if err := selfApprove(accReq, true); err != nil {
		t.Fatalf("a valid self-approval was refused at write: %v", err)
	}
	if s := findingStatusOf(h, acc); s != "accepted" {
		t.Fatalf("the self-approved acceptance did not apply: %s", s)
	}
}

// Lowering both levels in one change tells the approvers of both, not only
// the last one.
func TestFindingAcceptPolicy_NoticeNamesEveryLowering_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newAcceptPolicyHarness(t, rec)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	rec.reset()
	h.expect(owner, http.MethodPatch, "/api/v1/organization/settings/finding-approvals/",
		`{"fp_approval":"off","accept_approval":"off"}`, http.StatusOK)
	for _, p := range rec.inApp {
		if p.AudienceID != nil && p.AudienceID.String() == admin.id {
			if !strings.Contains(p.Body, "false-positive approval level") || !strings.Contains(p.Body, "risk acceptance approval level") {
				t.Fatalf("the notice hides a lowering: %q", p.Body)
			}
			return
		}
	}
	t.Fatalf("the other administrator was not told: %+v", rec.inApp)
}
