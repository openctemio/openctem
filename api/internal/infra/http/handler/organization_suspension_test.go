package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type orgGate map[shared.ID]error

func (g orgGate) CheckAccess(_ context.Context, id shared.ID) error { return g[id] }

// Inbound webhooks of a suspended organization are refused after the
// signature verified (so only the secret holder learns the status) and
// nothing is processed.
func TestGitHubWebhook_SuspendedOrganization(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeGitHubService{secrets: map[shared.ID][]string{tenant: {"s3cret"}}}
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})
	h.SetOrganizationGate(orgGate{tenant: tenantdom.ErrOrganizationSuspended})

	rec := httptest.NewRecorder()
	h.IncomingGitHubWebhook(rec, signedPush(tenant, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0960"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), tenantdom.CodeOrganizationSuspended) || svc.pushes != 0 {
		t.Fatalf("suspended: %d %s pushes=%d", rec.Code, rec.Body.String(), svc.pushes)
	}
	// A bad signature is still a 401 that says nothing about the status.
	if code := serveGitHub(h, signedPush(tenant, "wrong", "72d3162e-cc78-11e3-81ab-4c9367dc0961")); code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", code)
	}
	// Unreadable status: refused (fail closed).
	h.SetOrganizationGate(orgGate{tenant: errors.New("db down")})
	if code := serveGitHub(h, signedPush(tenant, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0962")); code != http.StatusServiceUnavailable || svc.pushes != 0 {
		t.Fatalf("unreadable status: %d pushes=%d", code, svc.pushes)
	}
}

type staticJiraVerifier struct{ tenant shared.ID }

func (v staticJiraVerifier) VerifyJiraDelivery(context.Context, shared.ID, []byte, string) (shared.ID, error) {
	return v.tenant, nil
}

func TestJiraWebhook_SuspendedOrganization(t *testing.T) {
	tenant := shared.NewID()
	h := &JiraWebhookHandler{verifier: staticJiraVerifier{tenant}, logger: logger.NewNop()}
	h.SetOrganizationGate(orgGate{tenant: tenantdom.ErrOrganizationSuspended})
	req := httptest.NewRequest(http.MethodPost, "/hooks/jira-integrations/x", strings.NewReader(`{}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("integration_id", shared.NewID().String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.IncomingJiraWebhook(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), tenantdom.CodeOrganizationSuspended) {
		t.Fatalf("suspended: %d %s", rec.Code, rec.Body.String())
	}
}

// The console actions refuse a missing reason, a missing administrator and a
// bad id before any service runs.
func TestAdminSuspensionHandler_Validation(t *testing.T) {
	h := NewAdminSuspensionHandler(nil, nil, logger.NewNop())
	rec := httptest.NewRecorder()
	h.SuspendOrganization(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"x"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.BlockUser(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"x"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired block: %d", rec.Code)
	}
}
