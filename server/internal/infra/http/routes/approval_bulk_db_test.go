package routes

// Deciding many approval requests at once, the sole member's own approval of
// a group exception and leaving one member out of a group, through the real
// routes and database (server/docs/architecture/finding-status-lifecycle.md,
// "Approvals"). Every path keeps four-eyes where the policy asks for it,
// another organization's ids answer as missing ones, and an approver
// outside a member's data scope reaches nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type approvalsBulkHarness struct {
	*approvalPolicyHarness
	codes *oneTimeCodes
	rec   *approvalNoticeRecorder
	repo  *postgres.FindingApprovalRepository
}

func newApprovalsBulkHarness(t *testing.T) *approvalsBulkHarness {
	gate := &approverStepUp{}
	codes := &oneTimeCodes{valid: map[string]bool{"111111": true, "222222": true, "333333": true, "444444": true}}
	rec := &approvalNoticeRecorder{}
	var repo *postgres.FindingApprovalRepository
	h := newFindingApprovalHarness(t, withDataScope, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, codes, ts)
		svc.SetApprovalNotifier(actors, rec, rec, "https://console.example.com")
		svc.SetStepUpGate(gate)
		svc.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
		vh.SetFindingApprovalSettings(ts)
		repo = postgres.NewFindingApprovalRepository(db)
	})
	return &approvalsBulkHarness{approvalPolicyHarness: &approvalPolicyHarness{findingApprovalHarness: h, stepUp: gate}, codes: codes, rec: rec, repo: repo}
}

// org is a tenant whose group exceptions are removed with its findings.
func (h *approvalsBulkHarness) org() string {
	id := h.tenantWithFindings()
	h.t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM approval_signoffs WHERE tenant_id = $1`,
			`DELETE FROM approval_batches WHERE tenant_id = $1`,
		} {
			_, _ = h.db.ExecContext(context.Background(), q, id)
		}
	})
	return id
}

// batch asks for one false-positive group over the findings, as requester
// (the selection of vulnerabilities source; no task to keep in step).
func (h *approvalsBulkHarness) batch(tenantID string, requester policyUser, findings ...string) string {
	h.t.Helper()
	ids := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, shared.MustIDFromString(f))
	}
	res, err := h.svc.RequestGroupException(context.Background(), finding.GroupExceptionInput{
		TenantID: shared.MustIDFromString(tenantID), SourceType: vulnerability.ApprovalBatchSourceVulnerabilities,
		SourceID: shared.NewID(), SourceLabel: "CVE-2026-0001", FindingIDs: ids, RequestedStatus: "false_positive",
		ClosureReason: "detection_error", Justification: "the scanner matched a banner, not the vulnerable code path",
		RequestedBy: shared.MustIDFromString(requester.id),
	})
	if err != nil {
		h.t.Fatalf("request group: %v", err)
	}
	return res.Batch.ID.String()
}

type batchDetailOut struct {
	ID                    string `json:"id"`
	Status                string `json:"status"`
	MemberCount           int    `json:"member_count"`
	SelfApprovalAvailable bool   `json:"self_approval_available"`
	Applied               *int   `json:"applied"`
	Members               []struct {
		FindingID string `json:"finding_id"`
		Status    string `json:"status"`
	} `json:"members"`
}

func (h *approvalsBulkHarness) batchDetail(u policyUser, id string) batchDetailOut {
	h.t.Helper()
	var out batchDetailOut
	_ = json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/approvals/batches/"+id, "", http.StatusOK)), &out)
	return out
}

func soloBody(code string) string {
	return `{"reason":"one-person company; checked every finding of the group","code":"` + code + `"}`
}

// The sole owner approves their own group with one fresh code and a reason:
// every member applied and marked self-approved, audited high, the backup
// contact told; a wrong or replayed code, another organization, a second
// active person and the single-request path all refuse.
func TestGroupException_SoleOwnerSelfApprove_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org, other := h.org(), h.org()
	owner, otherOwner := h.member(org, "owner"), h.member(other, "owner")
	h.expect(owner, http.MethodPatch, "/api/v1/organization/settings/finding-approvals/", `{"backup_contact_email":"advisor@example.com"}`, http.StatusOK)

	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(org, "high")
	b := h.batch(org, owner, f1, f2)
	if d := h.batchDetail(owner, b); !d.SelfApprovalAvailable || d.Status != "pending" {
		t.Fatalf("detail for the sole owner: %+v", d)
	}
	var list struct {
		Data []batchDetailOut `json:"data"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/approvals/batches?status=pending", "", http.StatusOK)), &list)
	if len(list.Data) != 1 || !list.Data[0].SelfApprovalAvailable {
		t.Fatalf("list for the sole owner: %+v", list.Data)
	}

	// A member is still never self-approved alone.
	var memberID string
	if err := h.db.QueryRowContext(context.Background(), `SELECT id FROM finding_status_approvals WHERE batch_id = $1 LIMIT 1`, b).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+memberID+"/self-approve", soloBody("111111"), http.StatusConflict)

	url := "/api/v1/approvals/batches/" + b + "/self-approve"
	h.expect(otherOwner, http.MethodPost, url, soloBody("111111"), http.StatusNotFound)
	h.expect(owner, http.MethodPost, url, soloBody("999999"), http.StatusForbidden)
	h.expect(owner, http.MethodPost, url, `{"reason":"","code":"111111"}`, http.StatusUnprocessableEntity)
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.self_approval_refused' AND resource_id = $2`, org, b); n != 1 {
		t.Fatalf("refusal audit rows: %d", n)
	}
	for _, f := range []string{f1, f2} {
		if st := findingStatusOf(h.findingApprovalHarness, f); st != "confirmed" {
			t.Fatalf("a refused self-approval moved %s to %s", f, st)
		}
	}

	h.rec.reset()
	var done batchDetailOut
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPost, url, soloBody("111111"), http.StatusOK)), &done)
	if done.Status != "approved" || done.Applied == nil || *done.Applied != 2 {
		t.Fatalf("self-approved group: %+v", done)
	}
	for _, f := range []string{f1, f2} {
		if st := findingStatusOf(h.findingApprovalHarness, f); st != "false_positive" {
			t.Fatalf("member %s: %s", f, st)
		}
		if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND (changes->>'self_approved')::boolean AND changes->>'batch_id' = $2`, f, b); n != 1 {
			t.Fatalf("timeline entries of %s: %d", f, n)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE batch_id = $1 AND self_approved AND self_approval_reason <> ''`, b); n != 2 {
		t.Fatalf("members marked self-approved: %d", n)
	}
	// One person alone is never recorded as a security review.
	if n := h.countRows(`SELECT COUNT(*) FROM findings WHERE id = ANY($1::uuid[]) AND verification IS NOT DISTINCT FROM 'security_review'`, "{"+f1+","+f2+"}"); n != 0 {
		t.Fatal("a self-approved group is labeled security-reviewed")
	}
	requireAudited(t, h.auditRows(org, "finding_approval.batch_self_approved"), b,
		[]auditRow{{action: "finding_approval.batch_self_approved", actor: owner.id, severity: "high"}})
	if len(h.rec.emails) != 1 || len(h.rec.emails[0]) != 1 || h.rec.emails[0][0] != "advisor@example.com" {
		t.Fatalf("backup contact email: %v", h.rec.emails)
	}
	if !strings.Contains(h.rec.bodies[0], "2 finding(s)") || strings.Contains(h.rec.bodies[0], "banner") {
		t.Fatalf("backup email names the count, never the note: %s", h.rec.bodies[0])
	}
	h.expect(owner, http.MethodPost, url, soloBody("222222"), http.StatusConflict)

	// A used code cannot be replayed.
	g1, _ := h.findingOnAsset(org, "low")
	b2 := h.batch(org, owner, g1)
	h.expect(owner, http.MethodPost, "/api/v1/approvals/batches/"+b2+"/self-approve", soloBody("111111"), http.StatusForbidden)

	// A second active person closes the path at once.
	h.member(org, "admin")
	if d := h.batchDetail(owner, b2); d.SelfApprovalAvailable {
		t.Fatal("self-approval offered with a second active member")
	}
	h.expect(owner, http.MethodPost, "/api/v1/approvals/batches/"+b2+"/self-approve", soloBody("333333"), http.StatusForbidden)
	if st := findingStatusOf(h.findingApprovalHarness, g1); st != "confirmed" {
		t.Fatalf("group of a two-person organization applied alone: %s", st)
	}
}

// A member suspended within the last 7 days keeps the sole owner from
// approving their own group (a stolen owner session cannot remove the other
// approver and self-approve), and no code is spent on the refusal.
func TestGroupException_SoloRefusedAfterRecentMemberRemoval_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org := h.org()
	owner := h.member(org, "owner")
	gone := h.member(org, "admin")
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() - interval '2 days' WHERE user_id = $1 AND tenant_id = $2`, gone.id, org)
	f, _ := h.findingOnAsset(org, "low")
	b := h.batch(org, owner, f)
	if d := h.batchDetail(owner, b); d.SelfApprovalAvailable {
		t.Fatal("self-approval offered right after a member was suspended")
	}
	out := map[string]any{}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPost, "/api/v1/approvals/batches/"+b+"/self-approve", soloBody("111111"), http.StatusForbidden)), &out)
	if out["code"] != "SELF_APPROVAL_AFTER_MEMBER_REMOVAL" {
		t.Fatalf("refusal: %v", out)
	}
	if !h.codes.valid["111111"] {
		t.Fatal("the refusal spent the code")
	}
	if st := findingStatusOf(h.findingApprovalHarness, f); st != "confirmed" {
		t.Fatalf("finding moved: %s", st)
	}
}

// An approver leaves one member out with a reason; the rest stays pending and
// is decided as usual. The requester cannot leave out from their own group,
// an approver outside a member's scope and another organization reach
// nothing, and the last member left out closes the group as rejected.
func TestGroupException_LeaveOutMember_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org, other := h.org(), h.org()
	requester, a1 := h.member(org, "admin"), h.member(org, "admin")
	outsider := h.member(other, "owner")
	narrow := h.member(org, "member")
	h.customRoleMember(narrow, org, permission.FindingsApprove, permission.FindingsRead)
	h.mintToken(&narrow, org)

	keep, _ := h.findingOnAsset(org, "low")
	drop, dropAsset := h.findingOnAsset(org, "low")
	b := h.batch(org, requester, keep, drop)
	url := func(f string) string { return "/api/v1/approvals/batches/" + b + "/items/" + f + "/reject" }
	body := `{"reason":"this host is in scope of the audit"}`

	h.expect(outsider, http.MethodPost, url(drop), body, http.StatusNotFound)
	// In scope for one member only: the group is out of their reach.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, narrow.id, org, dropAsset)
	h.expect(narrow, http.MethodPost, url(drop), body, http.StatusNotFound)
	h.expect(requester, http.MethodPost, url(drop), body, http.StatusBadRequest)
	h.expect(a1, http.MethodPost, url(drop), `{"reason":"  "}`, http.StatusBadRequest)
	h.expect(a1, http.MethodPost, url(uuid.NewString()), body, http.StatusNotFound)
	viewer := h.member(org, "viewer")
	h.expect(viewer, http.MethodPost, url(drop), body, http.StatusForbidden)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE batch_id = $1 AND status = 'pending'`, b); n != 2 {
		t.Fatalf("a refused leave-out changed members: %d pending", n)
	}

	h.rec.reset()
	var d batchDetailOut
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, url(drop), body, http.StatusOK)), &d)
	if d.Status != "pending" || d.MemberCount != 2 || len(d.Members) != 2 {
		t.Fatalf("after leaving one out: %+v", d)
	}
	for _, m := range d.Members {
		want := "pending"
		if m.FindingID == drop {
			want = "rejected"
		}
		if m.Status != want {
			t.Fatalf("member %s: %s, want %s", m.FindingID, m.Status, want)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_rejected' AND changes->>'batch_id' = $2 AND (changes->>'left_out')::boolean`, drop, b); n != 1 {
		t.Fatalf("timeline entry of the left-out member: %d", n)
	}
	requireAudited(t, h.auditRows(org, "finding_approval.batch_member_rejected"), b,
		[]auditRow{{action: "finding_approval.batch_member_rejected", actor: a1.id, severity: "medium"}})
	told := 0
	for _, p := range h.rec.inApp {
		if p.AudienceID != nil && p.AudienceID.String() == requester.id {
			told++
		}
	}
	if told != 1 {
		t.Fatalf("requester notices: %d", told)
	}
	h.expect(a1, http.MethodPost, url(drop), body, http.StatusConflict)

	// The group is approved without the left-out member.
	var done batchOut
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b+"/approve", "", http.StatusOK)), &done)
	if done.Status != "approved" || done.Applied == nil || *done.Applied != 1 {
		t.Fatalf("approval after leave-out: %+v", done)
	}
	if findingStatusOf(h.findingApprovalHarness, keep) != "false_positive" || findingStatusOf(h.findingApprovalHarness, drop) != "confirmed" {
		t.Fatal("members after the decision")
	}

	// Leaving out the last pending member closes the group as rejected.
	solo, _ := h.findingOnAsset(org, "low")
	b2 := h.batch(org, requester, solo)
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b2+"/items/"+solo+"/reject", body, http.StatusOK)), &d)
	if d.Status != "rejected" {
		t.Fatalf("group with no member left: %s", d.Status)
	}
}

type bulkOut struct {
	Results []struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		Outcome string `json:"outcome"`
		Code    string `json:"code"`
		Status  string `json:"status"`
	} `json:"results"`
	Approved, Signed, Rejected, Skipped, Failed int
}

func (h *approvalsBulkHarness) bulk(u policyUser, path, body string, want int) bulkOut {
	h.t.Helper()
	var out bulkOut
	_ = json.Unmarshal([]byte(h.expect(u, http.MethodPost, path, body, want)), &out)
	return out
}

func bulkOutcomes(o bulkOut) map[string]string {
	m := map[string]string{}
	for _, r := range o.Results {
		m[r.ID] = r.Outcome + "/" + r.Code
	}
	return m
}

func idsBody(approvals, batches []string, extra string) string {
	q := func(ids []string) string {
		if len(ids) == 0 {
			return "[]"
		}
		return `["` + strings.Join(ids, `","`) + `"]`
	}
	return fmt.Sprintf(`{"approval_ids":%s,"batch_ids":%s%s}`, q(approvals), q(batches), extra)
}

// Bulk approve and reject decide each id through its single path: requests
// and groups are applied, the requester's own request is refused, another
// organization's ids and ids outside the caller's scope are reported as not
// found and stay as they were, a replay reports not_pending, and the call is
// bounded and gated.
func TestApprovals_BulkApproveReject_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org, other := h.org(), h.org()
	requester, a1 := h.member(org, "admin"), h.member(org, "admin")
	otherOwner := h.member(other, "owner")
	narrow := h.member(org, "member")
	h.customRoleMember(narrow, org, permission.FindingsApprove, permission.FindingsRead)
	h.mintToken(&narrow, org)

	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(org, "medium")
	g1, _ := h.findingOnAsset(org, "low")
	own, _ := h.findingOnAsset(org, "low")
	r1, r2 := h.requestStatus(requester, f1, "false_positive"), h.requestStatus(requester, f2, "false_positive")
	mine := h.requestStatus(a1, own, "false_positive")
	b := h.batch(org, requester, g1)
	foreignF, _ := h.findingOnAsset(other, "low")
	foreign := h.requestStatus(otherOwner, foreignF, "false_positive")

	// Gate, bounds and body.
	viewer := h.member(org, "viewer")
	h.expect(viewer, http.MethodPost, "/api/v1/approvals/bulk/approve", idsBody([]string{r1}, nil, ""), http.StatusForbidden)
	many := make([]string, finding.MaxBulkApprovalDecisions+1)
	for i := range many {
		many[i] = uuid.NewString()
	}
	h.expect(a1, http.MethodPost, "/api/v1/approvals/bulk/approve", idsBody(many, nil, ""), http.StatusBadRequest)
	h.expect(a1, http.MethodPost, "/api/v1/approvals/bulk/approve", idsBody(nil, nil, ""), http.StatusBadRequest)
	h.expect(a1, http.MethodPost, "/api/v1/approvals/bulk/approve", `{"approval_ids":`, http.StatusBadRequest)

	// Another organization's caller on our ids: all not found, nothing moves.
	o := h.bulk(otherOwner, "/api/v1/approvals/bulk/reject", idsBody([]string{r1, r2}, []string{b}, `,"reason":"no"`), http.StatusOK)
	if o.Skipped != 3 || o.Rejected != 0 {
		t.Fatalf("cross-organization reject: %+v", o)
	}
	for _, v := range bulkOutcomes(o) {
		if v != "skipped/not_found" {
			t.Fatalf("cross-organization item: %s", v)
		}
	}
	// An approver who cannot see the findings: not found as well.
	o = h.bulk(narrow, "/api/v1/approvals/bulk/approve", idsBody([]string{r1}, []string{b}, ""), http.StatusOK)
	if o.Skipped != 2 || o.Approved != 0 {
		t.Fatalf("out-of-scope approve: %+v", o)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = ANY($1::uuid[]) AND status = 'pending'`, "{"+r1+","+r2+"}"); n != 2 {
		t.Fatal("a refused caller changed a request")
	}

	o = h.bulk(a1, "/api/v1/approvals/bulk/approve", idsBody([]string{r1, r2, mine, foreign, "not-an-id", r1}, []string{b}, ""), http.StatusOK)
	got := bulkOutcomes(o)
	want := map[string]string{
		r1: "approved/", r2: "approved/", b: "approved/", mine: "failed/own_request",
		foreign: "skipped/not_found", "not-an-id": "skipped/not_found",
	}
	if len(o.Results) != len(want) {
		t.Fatalf("results: %+v", o.Results)
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("item %s: %s, want %s (all: %v)", id, got[id], w, got)
		}
	}
	if o.Approved != 3 || o.Failed != 1 || o.Skipped != 2 {
		t.Fatalf("counts: %+v", o)
	}
	for _, f := range []string{f1, f2, g1} {
		if st := findingStatusOf(h.findingApprovalHarness, f); st != "false_positive" {
			t.Fatalf("approved member %s: %s", f, st)
		}
	}
	if st := findingStatusOf(h.findingApprovalHarness, own); st != "confirmed" {
		t.Fatalf("the caller's own request was applied: %s", st)
	}
	if st := findingStatusOf(h.findingApprovalHarness, foreignF); st != "confirmed" {
		t.Fatalf("another organization's finding moved: %s", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.approved' AND (metadata->>'bulk')::boolean`, org); n != 2 {
		t.Fatalf("bulk approvals audited: %d", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.self_approval_refused'`, org); n != 1 {
		t.Fatalf("own-request refusal audited: %d", n)
	}

	// A replay is safe by state.
	o = h.bulk(a1, "/api/v1/approvals/bulk/approve", idsBody([]string{r1}, []string{b}, ""), http.StatusOK)
	if o.Skipped != 2 {
		t.Fatalf("replay: %+v", o)
	}
	for _, v := range bulkOutcomes(o) {
		if v != "skipped/not_pending" {
			t.Fatalf("replayed item: %s", v)
		}
	}

	// Reject: a reason is required; the requester's own request may be
	// rejected by another approver.
	h.expect(requester, http.MethodPost, "/api/v1/approvals/bulk/reject", idsBody([]string{mine}, nil, `,"reason":""`), http.StatusBadRequest)
	h.expect(requester, http.MethodPost, "/api/v1/approvals/bulk/reject", idsBody([]string{mine}, nil, `,"reason":"`+strings.Repeat("x", 2001)+`"`), http.StatusBadRequest)
	o = h.bulk(requester, "/api/v1/approvals/bulk/reject", idsBody([]string{mine}, nil, `,"reason":"the fix is already deployed"`), http.StatusOK)
	if o.Rejected != 1 || o.Results[0].Status != "rejected" {
		t.Fatalf("bulk reject: %+v", o)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND status = 'rejected' AND rejection_reason = 'the fix is already deployed'`, mine); n != 1 {
		t.Fatal("the rejection was not stored with its reason")
	}
}

// A tier that needs a recent re-authentication of the approver keeps it in
// bulk: without it the item fails with step_up_required and nothing is
// recorded, while the other items are still decided.
func TestApprovals_BulkApproveKeepsStepUpPerTier_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org := h.org()
	requester, a1 := h.member(org, "admin"), h.member(org, "admin")
	high, _ := h.findingOnAsset(org, "high")
	req := h.requestAccept(requester, high)
	if req.Tier != "security" {
		t.Fatalf("high acceptance tier %s", req.Tier)
	}
	low, _ := h.findingOnAsset(org, "low")
	lowReq := h.requestStatus(requester, low, "false_positive")
	h.stepUp.refuse.Store(true)
	o := h.bulk(a1, "/api/v1/approvals/bulk/approve", idsBody([]string{req.ID, lowReq}, nil, ""), http.StatusOK)
	h.stepUp.refuse.Store(false)
	got := bulkOutcomes(o)
	if got[req.ID] != "failed/step_up_required" || got[lowReq] != "approved/" {
		t.Fatalf("outcomes: %v", got)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE subject_id = $1`, req.ID); n != 0 {
		t.Fatal("a refused approval was recorded")
	}
	if st := findingStatusOf(h.findingApprovalHarness, high); st != "confirmed" {
		t.Fatalf("decided without a step-up: %s", st)
	}
}

type cardRow struct {
	ID                    string   `json:"id"`
	PolicyReasons         []string `json:"policy_reasons"`
	EligibleApproverCount *int     `json:"eligible_approver_count"`
	SelfApprovalAvailable bool     `json:"self_approval_available"`
}

// A request row says why it waits and whether its requester may approve it
// alone: the stored reason codes, how many people could sign it off, and
// self_approval_available only for the sole owner's own request (never once
// a second person is active, never for someone else's request); another
// organization reads no row.
func TestFindingApprovals_CardSupportFields_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org, other := h.org(), h.org()
	owner, otherOwner := h.member(org, "owner"), h.member(other, "owner")
	f, _ := h.findingOnAsset(org, "low")
	a := h.requestStatus(owner, f, "false_positive")

	rows := func(u policyUser, finding string) []cardRow {
		var out []cardRow
		_ = json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/findings/"+finding+"/approvals/", "", http.StatusOK)), &out)
		return out
	}
	got := rows(owner, f)
	if len(got) != 1 || got[0].ID != a || !got[0].SelfApprovalAvailable || got[0].EligibleApproverCount == nil ||
		*got[0].EligibleApproverCount != 0 || len(got[0].PolicyReasons) == 0 {
		t.Fatalf("sole owner's own request: %+v", got)
	}
	var list struct {
		Data []cardRow `json:"data"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/approvals/?status=pending", "", http.StatusOK)), &list)
	if len(list.Data) != 1 || !list.Data[0].SelfApprovalAvailable || len(list.Data[0].PolicyReasons) == 0 {
		t.Fatalf("queue row: %+v", list.Data)
	}
	if got := rows(otherOwner, f); len(got) != 0 {
		t.Fatalf("another organization read a request: %+v", got)
	}

	// A second person: the path closes, and a new request counts them.
	admin := h.member(org, "admin")
	if got := rows(owner, f); got[0].SelfApprovalAvailable {
		t.Fatal("self-approval offered with a second active member")
	}
	if got := rows(admin, f); got[0].SelfApprovalAvailable {
		t.Fatal("self-approval offered on someone else's request")
	}
	g, _ := h.findingOnAsset(org, "low")
	h.requestStatus(owner, g, "false_positive")
	if got := rows(owner, g); got[0].EligibleApproverCount == nil || *got[0].EligibleApproverCount != 1 {
		t.Fatalf("eligible approvers with an admin: %+v", got)
	}
}

// The sole member's own approval of a group is checked again when it is
// written: a member active at that moment refuses the whole group in the
// same transaction, and no member is applied.
func TestGroupException_SoloRecheckedAtWrite_DB(t *testing.T) {
	h := newApprovalsBulkHarness(t)
	org := h.org()
	owner := h.member(org, "owner")
	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(org, "low")
	b := h.batch(org, owner, f1, f2)
	h.member(org, "admin") // joins after the service's check

	repo := h.repo
	tid, bid, uid := shared.MustIDFromString(org), shared.MustIDFromString(b), shared.MustIDFromString(owner.id)
	_, _, _, err := repo.SignOffBatch(context.Background(), tid, bid, uid, finding.SignoffRecord{UserID: uid},
		func([]approvalpolicy.Signoff) (bool, error) { return true, nil },
		func(a *vulnerability.Approval) (*vulnerability.FindingActivity, bool, error) {
			if err := a.SelfApprove(uid, "one-person company", false); err != nil {
				return nil, false, err
			}
			entry, err := vulnerability.NewFindingActivity(tid, a.FindingID, vulnerability.ActivityApprovalApproved,
				&uid, vulnerability.ActorTypeUser, map[string]any{"self_approved": true}, vulnerability.SourceAPI, nil)
			return entry, err == nil, err
		})
	if !errors.Is(err, vulnerability.ErrSoloApprovalNotAllowed) {
		t.Fatalf("group self-approval written with another active member: %v", err)
	}
	for _, f := range []string{f1, f2} {
		if st := findingStatusOf(h.findingApprovalHarness, f); st != "confirmed" {
			t.Fatalf("member %s moved: %s", f, st)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE batch_id = $1 AND status = 'pending'`, b); n != 2 {
		t.Fatalf("pending members after the refusal: %d", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_batches WHERE id = $1 AND status = 'pending'`, b); n != 1 {
		t.Fatal("the group did not stay pending")
	}
}
