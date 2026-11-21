package routes

// The admin roster actions keep the administrator's reason, over the real
// console routes (session, CSRF, step-up, audit middleware, four-eyes gate)
// and a migrated database: the action's audit row and the gate's row carry
// the trimmed reason; an over-long reason is refused with nothing changed; no
// reason still works (the reason is optional for now).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/adminapproval"
	"github.com/openctemio/openctem/server/internal/app/adminconsole"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func withRosterReason(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
	log := logger.NewNop()
	approvals := adminapproval.NewService(postgres.NewAdminApprovalRepository(db), postgres.NewAdminRepository(db),
		postgres.NewAuditLogRepository(db), log)
	h.AdminApproval = handler.NewAdminApprovalHandler(approvals, log)
	h.AdminConsole.WithApprovals(approvals)
	h.AdminUser = handler.NewAdminUserHandler(postgres.NewAdminRepository(db), log).WithApprovals(approvals)
	h.AdminAuditMiddleware = middleware.NewAuditMiddleware(postgres.NewAuditLogRepository(db), log)
}

// rosterTarget inserts an administrator nobody signs in as.
func (h *chainHarness) rosterTarget(role admin.AdminRole) *admin.AdminUser {
	h.t.Helper()
	a, err := admin.NewAdminUser("roster-reason-"+shared.NewID().String()+"@it.test", "Target", role, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.admins.Create(context.Background(), a); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM admin_approvals WHERE target = $1`, "admin:"+a.ID().String())
		_ = h.admins.Delete(context.Background(), a.ID())
	})
	return a
}

// auditRowReason waits for the audit row of action on resourceID (with the
// response status, when status > 0; the audit middleware writes its row in
// the background) and returns its "reason" and "request_reason".
func (h *chainHarness) auditRowReason(action, resourceID string, status int) (reason, requestReason sql.NullString) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := h.db.QueryRowContext(context.Background(), `SELECT request_body->>'reason', request_body->>'request_reason' FROM admin_audit_logs
			WHERE action = $1 AND resource_id::text = $2 AND ($3 = 0 OR response_status = $3)
			ORDER BY created_at DESC LIMIT 1`, action, resourceID, status).Scan(&reason, &requestReason)
		if err == nil {
			return reason, requestReason
		}
		if !errors.Is(err, sql.ErrNoRows) || time.Now().After(deadline) {
			h.t.Fatalf("audit row %s on %s (status %d): %v", action, resourceID, status, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// approve runs the four-eyes request the 428 refusal named: the requester
// asks with requestReason, the approver approves with a fresh code. It returns
// the approval id.
func approveRosterAction(t *testing.T, requester, approver *consoleAdmin, refusal, requestReason string) string {
	t.Helper()
	var r struct {
		Details handler.SecondApprovalDetails `json:"details"`
	}
	if err := json.Unmarshal([]byte(refusal), &r); err != nil || r.Details.Action == "" {
		t.Fatalf("refusal details: %v %s", err, refusal)
	}
	code, body := requester.do(http.MethodPost, "/api/v1/admin/approvals/",
		map[string]string{"action": r.Details.Action, "target": r.Details.Target, "reason": requestReason}, true)
	if code != http.StatusCreated {
		t.Fatalf("approval request: %d %s", code, body)
	}
	var req handler.AdminApprovalResponse
	_ = json.Unmarshal([]byte(body), &req)
	if req.Reason != requestReason {
		t.Fatalf("the approver sees the request reason: %s", body)
	}
	approver.resetReplayGuard()
	code, body = approver.do(http.MethodPost, "/api/v1/admin/approvals/"+req.ID+"/approve",
		map[string]string{"note": "checked", "totp_code": approver.freshCode(true)}, true)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	return req.ID
}

func TestAdminRosterActionsKeepTheReason_DB(t *testing.T) {
	h := newChainHarness(t, withRosterReason)
	a := h.newAdmin(admin.AdminRoleSuperAdmin)
	a.verify()
	b := h.newAdmin(admin.AdminRoleSuperAdmin) // a second super admin: approvals are on
	b.verify()
	t.Cleanup(func() {
		h.exec(`DELETE FROM admin_approvals WHERE requested_by IN ($1, $2)`, a.a.ID().String(), b.a.ID().String())
	})
	a.autoStepUp = true
	tooLong := strings.Repeat("a", 1001)

	t.Run("deactivate: the reason is kept, trimmed", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		code, body := a.do(http.MethodPatch, "/api/v1/admin/users/"+target.ID().String(),
			map[string]any{"is_active": false, "reason": "  left the team  "}, true)
		if code != http.StatusOK {
			t.Fatalf("deactivate: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(admin.AuditActionAdminUpdate, target.ID().String(), http.StatusOK); r.String != "left the team" {
			t.Fatalf("admin.update reason = %+v", r)
		}
	})

	t.Run("deactivate: an over-long reason is refused and not kept", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		code, body := a.do(http.MethodPatch, "/api/v1/admin/users/"+target.ID().String(),
			map[string]any{"is_active": false, "reason": tooLong}, true)
		if code != http.StatusBadRequest || !strings.Contains(body, `"code"`) {
			t.Fatalf("over-long reason: %d %s", code, body)
		}
		if got, err := h.admins.GetByID(context.Background(), target.ID()); err != nil || !got.IsActive() {
			t.Fatalf("nothing may change: %v", err)
		}
		if r, _ := h.auditRowReason(admin.AuditActionAdminUpdate, target.ID().String(), http.StatusBadRequest); r.Valid {
			t.Fatal("a refused reason must not be kept")
		}
	})

	t.Run("deactivate: no reason still works", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		code, body := a.do(http.MethodPatch, "/api/v1/admin/users/"+target.ID().String(), map[string]any{"is_active": false}, true)
		if code != http.StatusOK {
			t.Fatalf("deactivate without a reason: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(admin.AuditActionAdminUpdate, target.ID().String(), http.StatusOK); r.Valid {
			t.Fatalf("no reason given: the row has %q", r.String)
		}
	})

	t.Run("make super admin: the reason is kept in the update and approval rows", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		patch := map[string]any{"role": string(admin.AdminRoleSuperAdmin), "reason": " second on-call lead "}
		code, body := a.do(http.MethodPatch, "/api/v1/admin/users/"+target.ID().String(), patch, true)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("without approval: %d %s", code, body)
		}
		approvalID := approveRosterAction(t, a, b, body, "on-call rota needs a second super admin")
		if code, body = a.do(http.MethodPatch, "/api/v1/admin/users/"+target.ID().String(), patch, true); code != http.StatusOK {
			t.Fatalf("with approval: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(admin.AuditActionAdminUpdate, target.ID().String(), http.StatusOK); r.String != "second on-call lead" {
			t.Fatalf("admin.update reason = %+v", r)
		}
		r, rr := h.auditRowReason(adminapproval.ActionUsed, approvalID, 0)
		if r.String != "second on-call lead" || rr.String != "on-call rota needs a second super admin" {
			t.Fatalf("approval.used: reason %+v, request reason %+v", r, rr)
		}
	})

	t.Run("reset two-step: the reason is kept in the reset and approval rows", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		path := "/api/v1/admin/users/" + target.ID().String() + "/reset-credentials"
		if code, body := a.do(http.MethodPost, path, map[string]string{"reason": tooLong}, true); code != http.StatusBadRequest {
			t.Fatalf("over-long reason: %d %s", code, body)
		}
		code, body := a.do(http.MethodPost, path, map[string]string{"reason": "lost phone, ticket 42"}, true)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("without approval: %d %s", code, body)
		}
		approvalID := approveRosterAction(t, a, b, body, "lost authenticator")
		if code, body = a.do(http.MethodPost, path, map[string]string{"reason": "lost phone, ticket 42"}, true); code != http.StatusNoContent {
			t.Fatalf("with approval: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(adminconsole.ActionCredentialsReset, target.ID().String(), 0); r.String != "lost phone, ticket 42" {
			t.Fatalf("credentials reset reason = %+v", r)
		}
		if r, _ := h.auditRowReason(adminapproval.ActionUsed, approvalID, 0); r.String != "lost phone, ticket 42" {
			t.Fatalf("approval.used reason = %+v", r)
		}
	})

	t.Run("reset two-step: no reason still works", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		path := "/api/v1/admin/users/" + target.ID().String() + "/reset-credentials"
		code, body := a.do(http.MethodPost, path, nil, true)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("without approval: %d %s", code, body)
		}
		approveRosterAction(t, a, b, body, "lost authenticator")
		if code, body = a.do(http.MethodPost, path, nil, true); code != http.StatusNoContent {
			t.Fatalf("with approval, no body: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(adminconsole.ActionCredentialsReset, target.ID().String(), 0); r.Valid {
			t.Fatalf("no reason given: the row has %q", r.String)
		}
	})

	t.Run("break-glass test: the reason is kept", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleSuperAdmin)
		h.exec(`UPDATE admin_users SET is_break_glass = true, last_used_at = NOW() WHERE id = $1`, target.ID().String())
		path := "/api/v1/admin/users/" + target.ID().String() + "/break-glass-test"
		if code, body := a.do(http.MethodPost, path, map[string]string{"reason": tooLong}, true); code != http.StatusBadRequest {
			t.Fatalf("over-long reason: %d %s", code, body)
		}
		if code, body := a.do(http.MethodPost, path, map[string]string{"reason": " quarterly drill "}, true); code != http.StatusOK {
			t.Fatalf("break-glass test: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(adminconsole.ActionBreakGlassTested, target.ID().String(), 0); r.String != "quarterly drill" {
			t.Fatalf("break-glass test reason = %+v", r)
		}
	})

	t.Run("IdP unbind: the reason is kept", func(t *testing.T) {
		target := h.rosterTarget(admin.AdminRoleOpsAdmin)
		path := "/api/v1/admin/users/" + target.ID().String() + "/idp-binding"
		if code, body := a.do(http.MethodDelete, path, map[string]string{"reason": tooLong}, true); code != http.StatusBadRequest {
			t.Fatalf("over-long reason: %d %s", code, body)
		}
		if code, body := a.do(http.MethodDelete, path, map[string]string{"reason": "IdP account recreated"}, true); code != http.StatusNoContent {
			t.Fatalf("unbind: %d %s", code, body)
		}
		if r, _ := h.auditRowReason(adminconsole.ActionIdPUnbound, target.ID().String(), 0); r.String != "IdP account recreated" {
			t.Fatalf("unbind reason = %+v", r)
		}
	})
}
