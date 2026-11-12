package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubIdPRepo returns cur; reaching Save records it.
type stubIdPRepo struct {
	cur   *admin.PlatformIdP
	saved bool
}

func (r *stubIdPRepo) Get(context.Context) (*admin.PlatformIdP, error) {
	if r.cur == nil {
		return nil, admin.ErrPlatformIdPNotConfigured
	}
	return r.cur, nil
}
func (r *stubIdPRepo) Save(context.Context, *admin.PlatformIdP, bool) error {
	r.saved = true
	return nil
}
func (r *stubIdPRepo) Delete(context.Context) error { return nil }
func (r *stubIdPRepo) CreateLoginState(context.Context, *admin.IdPLoginState) error {
	return nil
}
func (r *stubIdPRepo) ConsumeLoginState(context.Context, string, time.Time) (*admin.IdPLoginState, error) {
	return nil, admin.ErrIdPLoginStateNotFound
}
func (r *stubIdPRepo) DeleteExpiredLoginStates(context.Context, time.Time) error { return nil }

func idpHandler(repo *stubIdPRepo, gate *fakeGate) *AdminConsoleHandler {
	svc := adminconsole.NewService(nil, nil, nil, nil, nil, logger.NewNop())
	svc.SetPlatformIdP(repo, nil) // no OIDC client: a save that gets past the gate fails, nothing is stored
	return NewAdminConsoleHandler(svc, true, logger.NewNop()).WithApprovals(gate)
}

func idpBody(enabled bool, issuer, clientID, amr string) string {
	return fmt.Sprintf(`{"enabled":%t,"display_name":"Corp","issuer":%q,"client_id":%q,"redirect_uri":"https://console.example/cb","trusted_amr_values":%s}`,
		enabled, issuer, clientID, amr)
}

func idpRequest(t *testing.T, issuer, clientID, amr string) *http.Request {
	return superAdminRequest(t, http.MethodPut, "/api/v1/admin/platform-idp", idpBody(true, issuer, clientID, amr))
}

func withIDParam(r *http.Request, id string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// A new issuer, a new client or a newly trusted AMR value needs a second
// super admin: 428 and nothing is saved.
func TestPutPlatformIdPChangeNeedsSecondApproval(t *testing.T) {
	cur := &admin.PlatformIdP{Enabled: true, Issuer: "https://idp.example.com", ClientID: "console",
		TrustedAMRValues: []string{"mfa"}}
	cases := map[string][3]string{
		"issuer":      {"https://evil.example.com", "console", `["mfa"]`},
		"client":      {"https://idp.example.com", "other", `["mfa"]`},
		"trusted amr": {"https://idp.example.com", "console", `["mfa","pwd"]`},
	}
	for name, c := range cases {
		repo := &stubIdPRepo{cur: cur}
		gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalPlatformIdPChange}}
		rec := httptest.NewRecorder()
		idpHandler(repo, gate).PutPlatformIdP(rec, idpRequest(t, c[0], c[1], c[2]))
		if rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s: status = %d %s, want 428", name, rec.Code, rec.Body.String())
		}
		if repo.saved {
			t.Fatalf("%s: nothing may be saved without the approval", name)
		}
		if len(gate.calls) != 1 || !strings.HasPrefix(gate.calls[0], "platform_idp.change ") {
			t.Fatalf("%s: gate calls = %v", name, gate.calls)
		}
		target := strings.TrimPrefix(gate.calls[0], "platform_idp.change ")
		if !admin.ApprovalPlatformIdPChange.ValidTarget(target) || !strings.Contains(target, c[0]) {
			t.Fatalf("%s: target %q must name the new configuration", name, target)
		}
	}
}

// A first configuration that trusts an AMR value needs the approval too.
func TestPutPlatformIdPFirstConfigWithTrustNeedsApproval(t *testing.T) {
	repo := &stubIdPRepo{}
	gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalPlatformIdPChange}}
	rec := httptest.NewRecorder()
	idpHandler(repo, gate).PutPlatformIdP(rec, idpRequest(t, "https://idp.example.com", "console", `["pwd"]`))
	if rec.Code != http.StatusPreconditionRequired || repo.saved {
		t.Fatalf("status = %d, saved = %v", rec.Code, repo.saved)
	}
}

// Edits that do not change who signs in, or that only tighten, ask nothing.
func TestPutPlatformIdPTighteningAsksNoApproval(t *testing.T) {
	cur := &admin.PlatformIdP{Enabled: true, Issuer: "https://idp.example.com", ClientID: "console",
		TrustedAMRValues: []string{"mfa", "hwk"}}
	repo := &stubIdPRepo{cur: cur}
	gate := &fakeGate{}
	rec := httptest.NewRecorder()
	idpHandler(repo, gate).PutPlatformIdP(rec, idpRequest(t, "https://idp.example.com", "console", `["mfa"]`))
	if len(gate.calls) != 0 {
		t.Fatalf("gate calls = %v, want none", gate.calls)
	}
}

// Disabling and changing in one request needs both approvals; when the second
// is missing, the first is handed back.
func TestPutPlatformIdPTwoApprovalsReleaseOnRefusal(t *testing.T) {
	cur := &admin.PlatformIdP{Enabled: true, Issuer: "https://idp.example.com", ClientID: "console"}
	repo := &stubIdPRepo{cur: cur}
	gate := &secondRefusingGate{}
	h := idpHandler(repo, nil)
	h.approvals = gate
	rec := httptest.NewRecorder()
	h.PutPlatformIdP(rec, superAdminRequest(t, http.MethodPut, "/api/v1/admin/platform-idp",
		idpBody(false, "https://evil.example.com", "console", `[]`)))
	if rec.Code != http.StatusPreconditionRequired || repo.saved {
		t.Fatalf("status = %d, saved = %v", rec.Code, repo.saved)
	}
	if len(gate.calls) != 2 || gate.released != 1 {
		t.Fatalf("calls = %v released = %d", gate.calls, gate.released)
	}
}

// secondRefusingGate grants the first approval and refuses the second.
type secondRefusingGate struct{ fakeGate }

func (g *secondRefusingGate) Require(ctx context.Context, a *admin.AdminUser, action admin.ApprovalAction, target string, c adminconsole.ClientInfo) (*adminapproval.Grant, error) {
	if len(g.calls) == 1 {
		g.calls = append(g.calls, string(action)+" "+target)
		return nil, &admin.ApprovalRequiredError{Action: action, Target: target}
	}
	return g.fakeGate.Require(ctx, a, action, target, c)
}

// Resetting another administrator's console second factor needs a second
// super admin; without it nothing is reset (svc is nil: reaching it panics).
func TestResetCredentialsNeedsSecondApproval(t *testing.T) {
	target := shared.NewID()
	gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalResetCredentials, Target: "admin:" + target.String()}}
	h := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
	req := superAdminRequest(t, http.MethodPost, "/api/v1/admin/users/"+target.String()+"/reset-credentials", "")
	req = withIDParam(req, target.String())
	rec := httptest.NewRecorder()
	h.ResetCredentials(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d %s, want 428", rec.Code, rec.Body.String())
	}
	if len(gate.calls) != 1 || gate.calls[0] != "admin.reset_credentials admin:"+target.String() {
		t.Fatalf("gate calls = %v", gate.calls)
	}
}
