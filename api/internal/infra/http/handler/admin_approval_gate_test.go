package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeGate records what the protected handler asked and answers with err.
type fakeGate struct {
	calls    []string
	err      error
	released int
}

func (g *fakeGate) Require(_ context.Context, _ *admin.AdminUser, action admin.ApprovalAction, target string, _ adminconsole.ClientInfo) (*adminapproval.Grant, error) {
	g.calls = append(g.calls, string(action)+" "+target)
	if g.err != nil {
		return nil, g.err
	}
	id := shared.NewID()
	return &adminapproval.Grant{ApprovalID: &id}, nil
}

func (g *fakeGate) Release(context.Context, *admin.AdminUser, *adminapproval.Grant, adminconsole.ClientInfo) {
	g.released++
}

func superAdminRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), middleware.AdminUserKey, a))
}

// Creating a super admin asks the gate with the exact, normalised email; a
// missing approval answers 428 SECOND_APPROVAL_REQUIRED and creates nothing.
func TestProvisionSuperAdminNeedsSecondApproval(t *testing.T) {
	pending := shared.NewID()
	gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalGrantSuperAdmin,
		Target: "email:new@example.com", PendingID: &pending}}
	// svc is nil: reaching the provisioning service would panic.
	h := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
	rec := httptest.NewRecorder()
	h.Provision(rec, superAdminRequest(t, http.MethodPost, "/api/v1/admin/administrators/",
		`{"email":"  New@Example.com ","name":"New","role":"super_admin"}`))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d %s, want 428", rec.Code, rec.Body.String())
	}
	var body struct {
		Code    string                `json:"code"`
		Details SecondApprovalDetails `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != string(CodeSecondApprovalRequired) || body.Details.PendingApprovalID != pending.String() ||
		body.Details.Action != string(admin.ApprovalGrantSuperAdmin) {
		t.Fatalf("body = %+v", body)
	}
	if len(gate.calls) != 1 || gate.calls[0] != "admin.grant_super_admin email:new@example.com" {
		t.Fatalf("gate calls = %v", gate.calls)
	}
}

// A gate that cannot run refuses the change (503), never lets it through.
func TestSecondApprovalGateFailsClosed(t *testing.T) {
	gate := &fakeGate{err: errors.New("audit log down")}
	h := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
	rec := httptest.NewRecorder()
	h.Provision(rec, superAdminRequest(t, http.MethodPost, "/api/v1/admin/administrators/",
		`{"email":"new@example.com","role":"super_admin"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// Every change that makes or unmakes an active super admin or an approver is
// classified; other changes are not gated.
func TestAdminRosterSuperAdminChange(t *testing.T) {
	cases := []struct {
		name   string
		before adminRosterState
		mutate func(a *admin.AdminUser)
		want   admin.ApprovalAction
	}{
		{"promote ops", adminRosterState{role: admin.AdminRoleOpsAdmin, active: true},
			func(a *admin.AdminUser) { _ = a.UpdateRole(admin.AdminRoleSuperAdmin) }, admin.ApprovalGrantSuperAdmin},
		{"reactivate super", adminRosterState{role: admin.AdminRoleSuperAdmin, active: false},
			func(a *admin.AdminUser) { a.Activate() }, admin.ApprovalGrantSuperAdmin},
		{"clear break-glass", adminRosterState{role: admin.AdminRoleSuperAdmin, active: true, breakGlass: true},
			func(a *admin.AdminUser) { _ = a.SetBreakGlass(false) }, admin.ApprovalGrantSuperAdmin},
		{"demote super", adminRosterState{role: admin.AdminRoleSuperAdmin, active: true},
			func(a *admin.AdminUser) { _ = a.UpdateRole(admin.AdminRoleReadonly) }, admin.ApprovalRevokeSuperAdmin},
		{"deactivate super", adminRosterState{role: admin.AdminRoleSuperAdmin, active: true},
			func(a *admin.AdminUser) { a.Deactivate() }, admin.ApprovalRevokeSuperAdmin},
		{"mark break-glass", adminRosterState{role: admin.AdminRoleSuperAdmin, active: true},
			func(a *admin.AdminUser) { _ = a.SetBreakGlass(true) }, admin.ApprovalRevokeSuperAdmin},
		{"rename super", adminRosterState{role: admin.AdminRoleSuperAdmin, active: true},
			func(a *admin.AdminUser) { _ = a.UpdateName("Renamed") }, ""},
		{"ops to readonly", adminRosterState{role: admin.AdminRoleOpsAdmin, active: true},
			func(a *admin.AdminUser) { _ = a.UpdateRole(admin.AdminRoleReadonly) }, ""},
		{"promote inactive", adminRosterState{role: admin.AdminRoleOpsAdmin, active: false},
			func(a *admin.AdminUser) { _ = a.UpdateRole(admin.AdminRoleSuperAdmin) }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := admin.NewAdminUser("x@example.com", "X", c.before.role, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !c.before.active {
				a.Deactivate()
			}
			if c.before.breakGlass {
				if err := a.SetBreakGlass(true); err != nil {
					t.Fatal(err)
				}
			}
			c.mutate(a)
			got, ok := c.before.superAdminChange(a)
			if got != c.want || ok != (c.want != "") {
				t.Fatalf("superAdminChange = %q, %v; want %q", got, ok, c.want)
			}
		})
	}
}
