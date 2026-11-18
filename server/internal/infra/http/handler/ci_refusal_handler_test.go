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
	tenant  shared.ID
	kind    string
	value   string
	configs []cirun.TrustConfig
}

func (f *fakeRefusalActions) UnverifiedRefusals(_ context.Context, tenantID shared.ID) ([]cirun.UnverifiedRefusal, []cirun.TrustConfig, error) {
	f.tenant = tenantID
	return []cirun.UnverifiedRefusal{{Issuer: "https://gitlab.example.com/", Reason: cirunapp.UnverifiedNotVerified, LastSeen: time.Now(), Count: 3},
		{Issuer: "", Reason: cirunapp.UnverifiedKeysUnavailable, Cause: cirunapp.IssuerCauseBlockedAddress, Count: 1}}, f.configs, nil
}

func (f *fakeRefusalActions) AllowInTrustConfig(_ context.Context, tenantID, id shared.ID, kind, value string, _ cirunapp.Actor) (*cirun.TrustConfig, bool, error) {
	f.tenant, f.kind, f.value = tenantID, kind, value
	if kind != cirunapp.AllowWorkflowRef && kind != cirunapp.AllowRef {
		return nil, false, cirunapp.ErrAllowKind
	}
	return &cirun.TrustConfig{ID: id, TenantID: tenantID, Name: "gl", Provider: cirun.ProviderGitLab}, true, nil
}

// The tenant comes from the session; the unverified list carries the
// nearest configured issuer and the cause class, never more.
func TestCIListUnverifiedRefusals(t *testing.T) {
	tenant := shared.NewID()
	h := NewCIAdminHandler(nil, nil, logger.NewNop())
	w := httptest.NewRecorder()
	h.ListUnverifiedRefusals(w, tenantRequest(http.MethodGet, "/", "", tenant))
	if w.Code != http.StatusNotFound {
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

func TestCIAllowInTrustConfig(t *testing.T) {
	tenant, id := shared.NewID(), shared.NewID()
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
	if w := call(`{"kind":"owner","value":"evil"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d %s", w.Code, w.Body.String())
	}
	if w := call(`{"kind":"ref","value":"release","tenant_id":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", w.Code)
	}
	w := call(`{"kind":"workflow_ref","value":"gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main"}`)
	if w.Code != http.StatusOK || f.tenant != tenant || f.kind != cirunapp.AllowWorkflowRef || !strings.Contains(w.Body.String(), `"changed":true`) {
		t.Fatalf("allow: %d %s", w.Code, w.Body.String())
	}
}
