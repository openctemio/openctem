package routes

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// findingApprovalHarness is the authorization-policy harness with the
// finding routes wired to the real finding service, approval repository and
// audit service, as in cmd/server.
type findingApprovalHarness struct {
	*authzPolicyHarness
	svc *finding.VulnerabilityService
}

func newFindingApprovalHarness(t *testing.T, configure ...func(*finding.VulnerabilityService, *handler.VulnerabilityHandler, *postgres.DB)) *findingApprovalHarness {
	t.Helper()
	out := &findingApprovalHarness{}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		svc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
		svc.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
		vh := handler.NewVulnerabilityHandler(svc, validator.New(), log)
		vh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		for _, c := range configure {
			c(svc, vh, db)
		}
		out.svc = svc
		hs.Vulnerability = vh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	out.authzPolicyHarness = newChangeAuditHarness(t)
	return out
}

// tenantWithFindings is a tenant whose findings, requests and timeline are
// removed before the tenant itself.
func (h *findingApprovalHarness) tenantWithFindings() string {
	id := h.tenant()
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM finding_status_approvals WHERE tenant_id = $1`,
			`DELETE FROM finding_activities WHERE tenant_id = $1`,
			`DELETE FROM notifications WHERE tenant_id = $1`,
			`DELETE FROM findings WHERE tenant_id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

func (h *findingApprovalHarness) newFinding(tenantID, severity string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'approval-route', 'm', $3, $1::text, 'confirmed')`, id, tenantID, severity)
	return id
}

func (h *findingApprovalHarness) requestStatus(u policyUser, findingID, status string) string {
	h.t.Helper()
	body := `{"requested_status":"` + status + `","justification":"the input is a constant"}`
	return decodeID(h.t, h.expect(u, http.MethodPost, "/api/v1/findings/"+findingID+"/approvals/", body, http.StatusCreated))
}

func (h *findingApprovalHarness) countRows(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// Conflicts answer 409, not 500: a second pending request on one finding,
// and a second approver deciding a request another person already approved.
func TestFindingApprovals_ConflictsAre409_DB(t *testing.T) {
	h := newFindingApprovalHarness(t)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	fid := h.newFinding(org, "medium")
	a := h.requestStatus(admin, fid, "false_positive")
	h.expect(admin, http.MethodPost, "/api/v1/findings/"+fid+"/approvals/",
		`{"requested_status":"accepted","justification":"again"}`, http.StatusConflict)
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+a+"/approve", "", http.StatusOK)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE finding_id = $1`, fid); n != 1 {
		t.Fatalf("requests: %d", n)
	}
}

// Every decision on a finding status request writes an audit row with the
// actor: request, approve, reject, cancel, and a refused attempt to approve
// one's own request. Another organization's owner reaches nothing and leaves
// no row in either organization.
func TestFindingApprovals_AuditTrail_DB(t *testing.T) {
	h := newFindingApprovalHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	otherOwner := h.member(other, "owner")

	f1, f2, f3 := h.newFinding(org, "medium"), h.newFinding(org, "low"), h.newFinding(org, "high")

	a1 := h.requestStatus(admin, f1, "false_positive")
	// The requester cannot approve: refused, and the refusal is audited.
	if code, body := h.do(admin, http.MethodPost, "/api/v1/approvals/"+a1+"/approve", ""); code < 400 || code >= 500 {
		t.Fatalf("self-approval: %d %s", code, body)
	}
	// Another organization's owner: 404, nothing audited.
	h.expect(otherOwner, http.MethodPost, "/api/v1/approvals/"+a1+"/approve", "", http.StatusNotFound)
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+a1+"/approve", "", http.StatusOK)

	a2 := h.requestStatus(admin, f2, "accepted")
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+a2+"/reject", `{"reason":"needs a compensating control"}`, http.StatusOK)

	a3 := h.requestStatus(admin, f3, "false_positive")
	h.expect(admin, http.MethodPost, "/api/v1/approvals/"+a3+"/cancel", "", http.StatusOK)

	rows := h.auditRows(org, "finding_approval.")
	requireAudited(t, rows, a1, []auditRow{
		{action: "finding_approval.requested", actor: admin.id},
		{action: "finding_approval.self_approval_refused", actor: admin.id, severity: "medium"},
		{action: "finding_approval.approved", actor: owner.id},
	})
	requireAudited(t, rows, a2, []auditRow{
		{action: "finding_approval.requested", actor: admin.id},
		{action: "finding_approval.rejected", actor: owner.id},
	})
	requireAudited(t, rows, a3, []auditRow{
		{action: "finding_approval.requested", actor: admin.id},
		{action: "finding_approval.canceled", actor: admin.id},
	})
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'finding_approval.%'`, other); n != 0 {
		t.Fatalf("another organization got %d finding approval audit rows", n)
	}
	// The audit row names the finding, never the justification text.
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
		AND action = 'finding_approval.requested' AND metadata->>'finding_id' = $3
		AND metadata::text NOT LIKE '%the input is a constant%'`, org, a1, f1); n != 1 {
		t.Fatalf("requested row metadata: %d", n)
	}
}
