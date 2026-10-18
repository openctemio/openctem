package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	adminconsole "github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// refusingGate answers every Require with the second-approval refusal.
type refusingGate struct {
	action admin.ApprovalAction
	target string
}

func (g *refusingGate) Require(_ context.Context, _ *admin.AdminUser, a admin.ApprovalAction, target string, _ adminconsole.ClientInfo) (*adminapproval.Grant, error) {
	g.action, g.target = a, target
	return nil, &admin.ApprovalRequiredError{Action: a, Target: target}
}

func (g *refusingGate) Release(context.Context, *admin.AdminUser, *adminapproval.Grant, adminconsole.ClientInfo) {
}

// Deleting an organization at once needs a second super admin: without an
// approval the call is refused with 428 before the deletion service is
// reached (the zero service would panic if it were).
func TestPurgeOrganization_NeedsSecondApproval(t *testing.T) {
	a, err := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := shared.NewID()
	gate := &refusingGate{}
	h := NewAdminSuspensionHandler(nil, nil, logger.NewNop()).WithApprovals(gate)
	h.SetOrganizationDeletion(&orgdeletion.Service{})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"customer asked for deletion"}`))
	req.SetPathValue(middleware.AdminTenantParam, id.String())
	req = req.WithContext(context.WithValue(req.Context(), middleware.AdminUserKey, a))
	rec := httptest.NewRecorder()
	h.PurgeOrganization(rec, req)

	if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), string(CodeSecondApprovalRequired)) {
		t.Fatalf("purge without approval: %d %s", rec.Code, rec.Body.String())
	}
	if gate.action != admin.ApprovalOrgPurge || gate.target != "tenant:"+id.String() {
		t.Fatalf("gate asked for %q %q", gate.action, gate.target)
	}
}
