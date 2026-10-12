package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeEASMVerifier struct {
	tenants []shared.ID
	err     error
	row     *verifieddomain.VerifiedDomain
}

func (f *fakeEASMVerifier) List(_ context.Context, tid shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	f.tenants = append(f.tenants, tid)
	return []*verifieddomain.VerifiedDomain{f.row}, f.err
}

func (f *fakeEASMVerifier) AddEASMDomain(_ context.Context, tid shared.ID, _ string) (*verifieddomain.VerifiedDomain, domainverify.TXTRecord, error) {
	f.tenants = append(f.tenants, tid)
	return f.row, domainverify.TXTRecord{}, f.err
}

func (f *fakeEASMVerifier) VerifyEASM(_ context.Context, tid, _ shared.ID) (*verifieddomain.VerifiedDomain, error) {
	f.tenants = append(f.tenants, tid)
	return f.row, f.err
}

func (f *fakeEASMVerifier) DeleteEASM(_ context.Context, tid, _ shared.ID) (*verifieddomain.VerifiedDomain, error) {
	f.tenants = append(f.tenants, tid)
	return f.row, f.err
}

type capturedAudit struct{ actions []auditdom.Action }

func (c *capturedAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	c.actions = append(c.actions, e.Action)
	return nil
}

func vdReq(method, target, body string, tenant shared.ID, id string) *http.Request {
	req := seedReq(method, target, body, tenant, "u1")
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
}

// The tenant always comes from the token, status codes map the service's
// errors (429 with Retry-After, 404 for another tenant's or an SSO row),
// an EASM row exposes its TXT record and an SSO row does not, and every
// change is audited.
func TestEASMVerifiedDomainHandler(t *testing.T) {
	tenant := shared.NewID()
	easmRow, _ := verifieddomain.New(shared.NewID(), tenant, "example.com", "tok")
	easmRow.WithPurpose(verifieddomain.PurposeEASM)
	f := &fakeEASMVerifier{row: easmRow}
	aud := &capturedAudit{}
	h := NewEASMVerifiedDomainHandler(f, aud, logger.NewNop())

	w := httptest.NewRecorder()
	h.Create(w, vdReq(http.MethodPost, "/", `{"domain":"example.com","tenant_id":"`+shared.NewID().String()+`"}`, tenant, ""))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "openctem-domain-verification=tok") ||
		!strings.Contains(w.Body.String(), `"purpose":"easm"`) {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	for _, tid := range f.tenants {
		if tid != tenant {
			t.Fatal("a tenant other than the token's reached the service")
		}
	}

	f.err = domainverify.ErrVerifyRateLimited
	w = httptest.NewRecorder()
	h.Verify(w, vdReq(http.MethodPost, "/", "", tenant, easmRow.ID().String()))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limited: %d", w.Code)
	}

	f.err = verifieddomain.ErrNotFound
	for _, call := range []func(http.ResponseWriter, *http.Request){h.Verify, h.Delete} {
		w = httptest.NewRecorder()
		call(w, vdReq(http.MethodPost, "/", "", tenant, easmRow.ID().String()))
		if w.Code != http.StatusNotFound {
			t.Fatalf("foreign row: %d", w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.Verify(w, vdReq(http.MethodPost, "/", "", tenant, "not-a-uuid"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", w.Code)
	}

	f.err = verifieddomain.ErrBlockedDomain
	w = httptest.NewRecorder()
	h.Create(w, vdReq(http.MethodPost, "/", `{"domain":"gmail.com"}`, tenant, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("blocked: %d", w.Code)
	}
	f.err = verifieddomain.ErrAlreadyExists
	w = httptest.NewRecorder()
	h.Create(w, vdReq(http.MethodPost, "/", `{"domain":"example.com"}`, tenant, ""))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", w.Code)
	}

	// An SSO row is listed without its TXT record and as managed.
	f.err = nil
	ssoRow, _ := verifieddomain.New(shared.NewID(), tenant, "corp.example", "secret-token")
	f.row = ssoRow
	w = httptest.NewRecorder()
	h.List(w, vdReq(http.MethodGet, "/", "", tenant, ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "secret-token") || !strings.Contains(w.Body.String(), `"managed":true`) {
		t.Fatalf("list sso row: %s", w.Body.String())
	}

	want := map[auditdom.Action]bool{auditdom.ActionEASMVerifiedDomainAdded: true, auditdom.ActionEASMVerifiedDomainThrottle: true}
	for a := range want {
		found := false
		for _, got := range aud.actions {
			found = found || got == a
		}
		if !found {
			t.Errorf("not audited: %s (%v)", a, aud.actions)
		}
	}
}
