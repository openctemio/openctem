package routes

// Four-eyes approvals over the real console routes (session, CSRF, role guard,
// step-up) and a migrated database: with a second super admin on the roster,
// re-signing an organization's audit chain is refused until another super
// admin approves; the requester cannot approve their own request; approving
// takes a fresh code; the approval works once and is audited critical.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify/chaintest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func withApprovals(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
	log := logger.NewNop()
	svc := adminapproval.NewService(postgres.NewAdminApprovalRepository(db), postgres.NewAdminRepository(db),
		postgres.NewAuditLogRepository(db), log)
	orgs := postgres.NewAdminOrganizationRepository(db)
	svc.SetTenantNamer(adminapproval.TenantNamerFunc(func(ctx context.Context, id shared.ID) (string, error) {
		o, err := orgs.GetOrganization(ctx, id)
		if err != nil {
			return "", err
		}
		return o.Name, nil
	}))
	h.AdminApproval = handler.NewAdminApprovalHandler(svc, log)
	h.AdminAuditChain.WithApprovals(svc)
	h.AdminConsole.WithApprovals(svc)
}

func TestFourEyes_RebaselineNeedsAnotherSuperAdmin_DB(t *testing.T) {
	h := newChainHarness(t, withApprovals)
	org := h.organization(4, chaintest.Current, chaintest.Legacy, chaintest.Current, chaintest.Pre79)
	a := h.newAdmin(admin.AdminRoleSuperAdmin)
	a.verify()
	b := h.newAdmin(admin.AdminRoleSuperAdmin)
	b.verify()
	t.Cleanup(func() {
		h.exec(`DELETE FROM admin_approvals WHERE requested_by IN ($1, $2)`, a.a.ID().String(), b.a.ID().String())
	})

	// Refused before anything is rewritten, naming the action and target.
	st := a.classify(org)
	before := h.chainHashes(org)
	code, body := a.rebaseline(org, st.Fingerprint, a.freshCode(true))
	if code != http.StatusPreconditionRequired || !strings.Contains(body, string(handler.CodeSecondApprovalRequired)) {
		t.Fatalf("rebaseline without approval: %d %s", code, body)
	}
	h.assertNotRewritten(org, before)
	var refusal struct {
		Details handler.SecondApprovalDetails `json:"details"`
	}
	_ = json.Unmarshal([]byte(body), &refusal)
	if refusal.Details.Action != string(admin.ApprovalAuditChainRebaseline) || refusal.Details.Target != "tenant:"+org {
		t.Fatalf("refusal details: %s", body)
	}

	// The requester asks (inside the step-up window the refused call opened).
	code, body = a.do(http.MethodPost, "/api/v1/admin/approvals/",
		map[string]string{"action": refusal.Details.Action, "target": refusal.Details.Target, "reason": "breaks explained by the old hash format"}, true)
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, body)
	}
	var req handler.AdminApprovalResponse
	_ = json.Unmarshal([]byte(body), &req)
	if req.Status != admin.ApprovalPending || req.TargetLabel != "Audit chain IT" || !req.Mine {
		t.Fatalf("request: %s", body)
	}

	// Not by the requester, even with a fresh code.
	a.resetReplayGuard()
	code, body = a.do(http.MethodPost, "/api/v1/admin/approvals/"+req.ID+"/approve",
		map[string]string{"note": "self", "totp_code": a.freshCode(false)}, true)
	if code != http.StatusForbidden {
		t.Fatalf("self approval: %d %s", code, body)
	}
	// Approving takes a fresh code even inside a step-up window.
	if code, body = b.do(http.MethodPost, "/api/v1/admin/approvals/"+req.ID+"/approve", map[string]string{"note": "checked"}, true); code != http.StatusUnauthorized {
		t.Fatalf("approve without a fresh code: %d %s", code, body)
	}
	code, body = b.do(http.MethodPost, "/api/v1/admin/approvals/"+req.ID+"/approve",
		map[string]string{"note": "checked with the requester", "totp_code": b.freshCode(true)}, true)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}

	// The requester repeats the action: it runs once.
	a.resetReplayGuard()
	st = a.classify(org)
	if code, body = a.rebaseline(org, st.Fingerprint, a.freshCode(false)); code != http.StatusOK {
		t.Fatalf("rebaseline with approval: %d %s", code, body)
	}
	a.resetReplayGuard()
	st = a.classify(org)
	if code, body = a.rebaseline(org, st.Fingerprint, a.freshCode(false)); code != http.StatusPreconditionRequired {
		t.Fatalf("second rebaseline on one approval: %d %s", code, body)
	}

	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM admin_audit_logs WHERE severity = 'critical' AND resource_type = 'admin_approval'
		AND resource_id = $1 AND action IN ('approval.requested', 'approval.approved', 'approval.used')`, req.ID).Scan(&n)
	if n != 3 {
		t.Fatalf("critical audit rows for the approval: %d, want 3", n)
	}
}
