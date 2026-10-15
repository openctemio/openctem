package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// vdMem is a tenant-scoped in-memory verified-domain repository.
type vdMem struct {
	rows map[string]*verifieddomain.VerifiedDomain
}

func (m *vdMem) Create(_ context.Context, d *verifieddomain.VerifiedDomain) error {
	m.rows[d.ID().String()] = d
	return nil
}
func (m *vdMem) Update(_ context.Context, d *verifieddomain.VerifiedDomain) error {
	m.rows[d.ID().String()] = d
	return nil
}
func (m *vdMem) Delete(context.Context, shared.ID, shared.ID) error { return nil }
func (m *vdMem) GetByID(_ context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	r, ok := m.rows[id.String()]
	if !ok || !r.TenantID().Equals(tenantID) {
		return nil, verifieddomain.ErrNotFound
	}
	return r, nil
}
func (m *vdMem) GetByTenantAndDomain(context.Context, shared.ID, string) (*verifieddomain.VerifiedDomain, error) {
	return nil, verifieddomain.ErrNotFound
}
func (m *vdMem) ListByTenant(_ context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	var out []*verifieddomain.VerifiedDomain
	for _, r := range m.rows {
		if r.TenantID().Equals(tenantID) {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *vdMem) ListDueForRecheck(context.Context, time.Time, int) ([]*verifieddomain.VerifiedDomain, error) {
	return nil, nil
}
func (m *vdMem) ListSSOClaims(context.Context, string) ([]*verifieddomain.VerifiedDomain, error) {
	return nil, nil
}

func domainPolicyRequest(method, path, body string, tenantID shared.ID, domainID string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("domainId", domainID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	return r.WithContext(context.WithValue(ctx, middleware.TeamIDKey, tenantID))
}

// Settings > Domains is scoped to the caller's organization: another
// organization neither lists nor changes the domain (404), and a valid owner
// change is stored.
func TestDomainSignupPolicyHandler_TenantIsolation(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	repo := &vdMem{rows: map[string]*verifieddomain.VerifiedDomain{}}
	vd, _ := verifieddomain.New(shared.NewID(), tenantA, "acme-iso.example", "tok")
	vd.WithPurpose(verifieddomain.PurposeSSO)
	vd.MarkVerified(time.Now())
	_ = repo.Create(context.Background(), vd)

	h := NewTenantHandler(nil, nil, logger.NewNop())
	h.SetDomainSignupPolicy(domainverify.NewService(repo, nil, logger.NewNop()), nil)

	rec := httptest.NewRecorder()
	h.ListDomainSignupPolicies(rec, domainPolicyRequest(http.MethodGet, "/", "", tenantB, ""))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "acme-iso.example") {
		t.Fatalf("another organization must not see the domain: %d %s", rec.Code, rec.Body.String())
	}

	body := `{"join_policy":"auto","join_role":"member","discoverable":true}`
	rec = httptest.NewRecorder()
	h.UpdateDomainSignupPolicy(rec, domainPolicyRequest(http.MethodPut, "/", body, tenantB, vd.ID().String()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant change must be 404, got %d %s", rec.Code, rec.Body.String())
	}
	if vd.SignupPolicy().Join != verifieddomain.JoinOff {
		t.Fatal("a refused change writes nothing")
	}

	rec = httptest.NewRecorder()
	h.UpdateDomainSignupPolicy(rec, domainPolicyRequest(http.MethodPut, "/", `{"join_policy":"everyone","join_role":"viewer"}`, tenantA, vd.ID().String()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown join policy must be 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.UpdateDomainSignupPolicy(rec, domainPolicyRequest(http.MethodPut, "/", `{"join_policy":"auto","join_role":"admin"}`, tenantA, vd.ID().String()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("joining as an administrator must be refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.UpdateDomainSignupPolicy(rec, domainPolicyRequest(http.MethodPut, "/", `{"join_policy":"off","join_role":"viewer","sso_required":true}`, tenantA, vd.ID().String()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sso_required without SSO must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.UpdateDomainSignupPolicy(rec, domainPolicyRequest(http.MethodPut, "/", body, tenantA, vd.ID().String()))
	if rec.Code != http.StatusOK || vd.SignupPolicy().Join != verifieddomain.JoinAuto || !vd.SignupPolicy().Discoverable {
		t.Fatalf("owner change: %d %s", rec.Code, rec.Body.String())
	}
}
