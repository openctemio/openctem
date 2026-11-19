package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeRefusalActions struct {
	tenant    shared.ID
	refusalID shared.ID
	configs   []cirun.TrustConfig
	notFit    bool
}

func (f *fakeRefusalActions) UnverifiedRefusals(_ context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, []cirun.TrustConfig, error) {
	f.tenant = tenantID
	return []cirun.UnverifiedRefusal{{Issuer: "https://gitlab.example.com/", Reason: cirunapp.UnverifiedNotVerified, LastSeen: time.Now(), Count: 3},
		{Issuer: "", Reason: cirunapp.UnverifiedKeysUnavailable, Cause: cirunapp.IssuerCauseBlockedAddress, Count: 1}}, f.configs, nil
}

func (f *fakeRefusalActions) AllowInTrustConfig(_ context.Context, tenantID, id, refusalID shared.ID, _ cirunapp.Actor) (*cirun.TrustConfig, cirunapp.Allowed, bool, error) {
	f.tenant, f.refusalID = tenantID, refusalID
	if f.notFit {
		return nil, cirunapp.Allowed{}, false, cirunapp.ErrAllowNotApplicable
	}
	return &cirun.TrustConfig{ID: id, TenantID: tenantID, Name: "gl", Provider: cirun.ProviderGitLab},
		cirunapp.Allowed{Kind: cirunapp.AllowRef, Value: "release"}, true, nil
}

// The tenant comes from the session; the unverified list carries the
// nearest configured issuer and the cause class, never more.
func TestCIListUnverifiedRefusals(t *testing.T) {
	tenant := shared.NewID()
	h := NewCIAdminHandler(nil, nil, logger.NewNop())
	w := httptest.NewRecorder()
	h.ListUnverifiedRefusals(w, tenantRequest(http.MethodGet, "/", "", tenant))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %d", w.Code)
	}
	cfgID := shared.NewID()
	f := &fakeRefusalActions{configs: []cirun.TrustConfig{{ID: cfgID, Name: "gl", Provider: cirun.ProviderGitLab, Issuer: "https://gitlab.example.com", Enabled: true}}}
	h.SetRefusalActions(f)
	w = httptest.NewRecorder()
	h.ListUnverifiedRefusals(w, tenantRequest(http.MethodGet, "/", "", tenant))
	body := w.Body.String()
	if w.Code != http.StatusOK || f.tenant != tenant {
		t.Fatalf("list: %d %s", w.Code, body)
	}
	for _, want := range []string{`"nearest_issuer":"https://gitlab.example.com"`, `"difference":"trailing_slash"`,
		`"cause":"blocked_address"`, `"configured_issuers":[{"config_id":"` + cfgID.String()} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}
}

// The one-click fix names a refusal, never a value: a free-text kind or
// value is refused, the tenant comes from the session, and a refusal the
// configuration cannot take answers 400.
func TestCIAllowInTrustConfig(t *testing.T) {
	tenant, id, refusal := shared.NewID(), shared.NewID(), shared.NewID()
	h := NewCIAdminHandler(nil, nil, logger.NewNop())
	f := &fakeRefusalActions{}
	h.SetRefusalActions(f)
	call := func(body string) *httptest.ResponseRecorder {
		r := tenantRequest(http.MethodPost, "/", body, tenant)
		r.SetPathValue("id", id.String())
		w := httptest.NewRecorder()
		h.AllowInTrustConfig(w, r)
		return w
	}
	for _, body := range []string{`{"kind":"ref","value":"release"}`, `{"refusal_id":"x"}`,
		`{"refusal_id":"` + refusal.String() + `","value":"evil"}`} {
		if w := call(body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	w := call(`{"refusal_id":"` + refusal.String() + `"}`)
	if w.Code != http.StatusOK || f.tenant != tenant || f.refusalID != refusal ||
		!strings.Contains(w.Body.String(), `"changed":true`) || !strings.Contains(w.Body.String(), `"value":"release"`) {
		t.Fatalf("allow: %d %s", w.Code, w.Body.String())
	}
	f.notFit = true
	if w := call(`{"refusal_id":"` + refusal.String() + `"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("refusal the configuration cannot take: %d %s", w.Code, w.Body.String())
	}
}
