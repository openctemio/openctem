package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// oneTimeCodes accepts each listed code once (a used code is refused, as
// the real authenticator check does).
type oneTimeCodes struct {
	mu    sync.Mutex
	valid map[string]bool
}

func (c *oneTimeCodes) VerifyFreshTOTP(_ context.Context, _, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid[code] {
		return vulnerability.ErrSoloApprovalBadCode
	}
	delete(c.valid, code)
	return nil
}

type soloHarness struct {
	*findingApprovalHarness
	codes *oneTimeCodes
	rec   *approvalNoticeRecorder
}

func newSoloHarness(t *testing.T) *soloHarness {
	codes := &oneTimeCodes{valid: map[string]bool{"111111": true, "222222": true, "333333": true, "444444": true}}
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetApprovalNotifier(actors, rec, rec, "https://console.example.com")
		svc.SetSoloApproval(actors, codes, ts)
		vh.SetFindingApprovalSettings(ts)
	})
	return &soloHarness{findingApprovalHarness: h, codes: codes, rec: rec}
}

func (h *soloHarness) selfApprove(u policyUser, approvalID, code string, want int) map[string]any {
	h.t.Helper()
	body := `{"reason":"one-person company; reviewed the trace myself","code":"` + code + `"}`
	out := map[string]any{}
	_ = json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/approvals/"+approvalID+"/self-approve", body, want)), &out)
	return out
}

func (h *soloHarness) requestAccept(u policyUser, findingID string, end time.Time) string {
	h.t.Helper()
	body := `{"requested_status":"accepted","justification":"vendor patch next quarter","expires_at":"` + end.UTC().Format(time.RFC3339) + `"}`
	return decodeID(h.t, h.expect(u, http.MethodPost, "/api/v1/findings/"+findingID+"/approvals/", body, http.StatusCreated))
}

func (h *soloHarness) listSelfApprovalAvailable(u policyUser) bool {
	h.t.Helper()
	var out struct {
		Available bool `json:"self_approval_available"`
	}
	_ = json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/approvals/?status=pending", "", http.StatusOK)), &out)
	return out.Available
}

// The owner of an organization with no other active person may approve
// their own request with a fresh authenticator code and a reason: refused
// without a valid code (audited), allowed with one (audited high, marked
// self_approved, channels and backup contact told), an accepted risk is cut
// to the short self-approval limit (7 days for KEV), and the path closes the
// moment a second active person exists. Suspended members and service
// accounts do not count; another organization reaches nothing.
func TestFindingApprovals_SoleOwnerSelfApproval_DB(t *testing.T) {
	h := newSoloHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner := h.member(org, "owner")
	otherOwner := h.member(other, "owner")

	// A suspended member and a service account do not make a second person.
	suspended := h.member(org, "member")
	h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, suspended.id, org)
	svcID := uuid.NewString()
	h.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id) VALUES ($1, $2, 'ci bot', 'service', $3)`, svcID, "svc-"+svcID[:8]+"@it.test", org)
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, svcID) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, svcID, org)

	// The backup contact (settings:write + step-up; audited).
	h.expect(owner, http.MethodPut, "/api/v1/organization/settings/finding-approvals/", `{"backup_contact_email":"Advisor@Example.com"}`, http.StatusOK)
	h.expect(owner, http.MethodPut, "/api/v1/organization/settings/finding-approvals/", `{"backup_contact_email":"not an email"}`, http.StatusBadRequest)
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.settings_changed'`, org); n != 1 {
		t.Fatalf("settings audit rows: %d", n)
	}

	if !h.listSelfApprovalAvailable(owner) {
		t.Fatal("the sole owner is not offered self-approval")
	}

	fp := h.newFinding(org, "medium")
	a1 := h.requestStatus(owner, fp, "false_positive")
	// Without a valid code: refused and audited; the code is not spent.
	h.selfApprove(owner, a1, "999999", http.StatusForbidden)
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.self_approval_refused' AND resource_id = $2`, org, a1); n != 1 {
		t.Fatalf("refusal audit rows: %d", n)
	}
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+a1+"/self-approve", `{"reason":"","code":"111111"}`, http.StatusUnprocessableEntity)
	// Another organization's owner: 404.
	h.expect(otherOwner, http.MethodPost, "/api/v1/approvals/"+a1+"/self-approve", `{"reason":"x","code":"111111"}`, http.StatusNotFound)

	h.rec.reset()
	got := h.selfApprove(owner, a1, "111111", http.StatusOK)
	if got["status"] != "approved" || got["self_approved"] != true {
		t.Fatalf("self-approved request: %v", got)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM findings WHERE id = $1 AND status = 'false_positive'`, fp); n != 1 {
		t.Fatal("the finding did not become a false positive")
	}
	requireAudited(t, h.auditRows(org, "finding_approval.self_approved"), a1,
		[]auditRow{{action: "finding_approval.self_approved", actor: owner.id, severity: "high"}})
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND (changes->>'self_approved')::boolean`, fp); n != 1 {
		t.Fatalf("timeline entries marked self-approved: %d", n)
	}
	if len(h.rec.emails) != 1 || len(h.rec.emails[0]) != 1 || h.rec.emails[0][0] != "advisor@example.com" {
		t.Fatalf("backup contact email: %v", h.rec.emails)
	}
	// A used code cannot be replayed.
	fp2 := h.newFinding(org, "low")
	a2 := h.requestStatus(owner, fp2, "false_positive")
	h.selfApprove(owner, a2, "111111", http.StatusForbidden)

	// An accepted risk is cut to the self-approval limit: 7 days for KEV.
	kev := h.newFinding(org, "high")
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	a3 := h.requestAccept(owner, kev, time.Now().AddDate(0, 6, 0))
	got = h.selfApprove(owner, a3, "222222", http.StatusOK)
	if got["end_shortened"] != true {
		t.Fatalf("a 6-month acceptance was not shortened: %v", got)
	}
	var end time.Time
	if err := h.db.QueryRowContext(context.Background(), `SELECT acceptance_expires_at FROM findings WHERE id = $1`, kev).Scan(&end); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(end); d > 7*24*time.Hour+time.Minute || d < 6*24*time.Hour {
		t.Fatalf("KEV self-acceptance ends in %v, want 7 days", d)
	}

	// A second active person closes the path at once (checked at decision time).
	h.member(org, "admin")
	if h.listSelfApprovalAvailable(owner) {
		t.Fatal("self-approval offered with a second active member")
	}
	h.selfApprove(owner, a2, "333333", http.StatusForbidden)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND status = 'pending'`, a2); n != 1 {
		t.Fatal("the request did not stay pending")
	}
}

// Only the owner may use it, only on their own request, and a member
// without settings:write cannot change the backup contact.
func TestFindingApprovals_SelfApprovalOnlyOwnRequest_DB(t *testing.T) {
	h := newSoloHarness(t)
	org := h.tenantWithFindings()
	owner, member := h.member(org, "owner"), h.member(org, "member")
	h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, member.id, org)
	f := h.newFinding(org, "low")
	// An AI proposal (requested by nobody) is not the owner's own request.
	ok, err := h.svc.ProposeFalsePositiveFromAI(context.Background(), shared.MustIDFromString(org), shared.MustIDFromString(f), 0.95, "fixture")
	if err != nil || !ok {
		t.Fatalf("proposal: %v %v", ok, err)
	}
	var aid string
	if err := h.db.QueryRowContext(context.Background(), `SELECT id::text FROM finding_status_approvals WHERE finding_id = $1`, f).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	out := h.selfApprove(owner, aid, "444444", http.StatusForbidden)
	if !strings.Contains(strings.ToUpper(out["code"].(string)), "SELF_APPROVAL_NOT_ALLOWED") {
		t.Fatalf("refusal code: %v", out)
	}
	h.exec(`UPDATE tenant_members SET status = 'active' WHERE user_id = $1 AND tenant_id = $2`, member.id, org)
	h.expect(member, http.MethodPut, "/api/v1/organization/settings/finding-approvals/", `{"backup_contact_email":"x@example.com"}`, http.StatusForbidden)
}

// A member suspended or removed in the last 7 days keeps the sole owner from
// approving their own request (a stolen owner session cannot remove the other
// approver and self-approve); after 7 days the path opens. Another
// organization's changes do not count.
func TestFindingApprovals_SoloRefusedAfterRecentMemberRemoval_DB(t *testing.T) {
	h := newSoloHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner := h.member(org, "owner")
	gone := h.member(org, "admin")
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() - interval '2 days' WHERE user_id = $1 AND tenant_id = $2`, gone.id, org)
	// A removal in another organization does not count.
	otherGone := h.member(other, "admin")
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE user_id = $1 AND tenant_id = $2`, otherGone.id, other)

	f := h.newFinding(org, "low")
	a := h.requestStatus(owner, f, "false_positive")
	if h.listSelfApprovalAvailable(owner) {
		t.Fatal("self-approval offered right after a member was suspended")
	}
	out := h.selfApprove(owner, a, "111111", http.StatusForbidden)
	if out["code"] != "SELF_APPROVAL_AFTER_MEMBER_REMOVAL" {
		t.Fatalf("refusal: %v", out)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.self_approval_refused' AND resource_id = $2`, org, a); n != 1 {
		t.Fatalf("refusal audit rows: %d", n)
	}
	// A member deleted outright shows only in the audit log.
	h.exec(`UPDATE tenant_members SET suspended_at = now() - interval '8 days' WHERE user_id = $1 AND tenant_id = $2`, gone.id, org)
	h.exec(`INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, logged_at)
		VALUES (gen_random_uuid(), $1, 'member.removed', 'membership', 'x', 'success', 'medium', 'removed', now() - interval '3 days')`, org)
	h.selfApprove(owner, a, "111111", http.StatusForbidden)
	// Eight days later the path opens.
	h.exec(`UPDATE audit_logs SET logged_at = now() - interval '8 days' WHERE tenant_id = $1 AND action = 'member.removed'`, org)
	if !h.listSelfApprovalAvailable(owner) {
		t.Fatal("self-approval still closed after 7 days")
	}
	h.selfApprove(owner, a, "222222", http.StatusOK)
}
