package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type stubAIStore struct {
	view    tenantai.View
	err     error
	gotTID  string
	gotSave tenantai.Update
	test    tenantai.TestResult
}

func (s *stubAIStore) Get(_ context.Context, tid string) (tenantai.View, error) {
	s.gotTID = tid
	return s.view, s.err
}

func (s *stubAIStore) Save(_ context.Context, tid string, in tenantai.Update, _ auditapp.AuditContext) (tenantai.View, error) {
	s.gotTID, s.gotSave = tid, in
	return s.view, s.err
}

func (s *stubAIStore) Test(_ context.Context, tid string, in tenantai.Update, _ auditapp.AuditContext) (tenantai.TestResult, error) {
	s.gotTID, s.gotSave = tid, in
	return s.test, s.err
}

func aiReq(method, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/organization/settings/ai", strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, "11111111-1111-7111-8111-111111111111"))
}

// The response says whether a key is set, its last four characters and when
// it was set, and never the key. The tenant comes from the context only.
func TestAISettingsHandler_NeverReturnsTheKey(t *testing.T) {
	now := time.Now().UTC()
	store := &stubAIStore{view: tenantai.View{Source: "own", Provider: "openai", Model: "gpt-4o", KeySet: true, KeyLast4: "6789", KeyUpdatedAt: &now, KeyUpdatedBy: "u1", OwnProviderAllowed: true}}
	h := NewAISettingsHandler(store, validator.New(), logger.NewNop())

	rec := httptest.NewRecorder()
	h.Get(rec, aiReq(http.MethodGet, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	key := got["key"].(map[string]any)
	if key["set"] != true || key["last4"] != "6789" || key["updated_by"] != "u1" {
		t.Fatalf("key info: %v", key)
	}
	for k := range got {
		if k == "api_key" {
			t.Fatal("the response must have no api_key field")
		}
	}
	if store.gotTID != "11111111-1111-7111-8111-111111111111" {
		t.Fatalf("tenant %q", store.gotTID)
	}

	// Saving returns the same shape and passes the key through to the service only.
	rec = httptest.NewRecorder()
	h.Update(rec, aiReq(http.MethodPut, `{"source":"own","provider":"openai","api_key":"sk-fake-secret-0123456789"}`))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sk-fake-secret") {
		t.Fatalf("status %d, body leaks the key: %s", rec.Code, rec.Body)
	}
	if store.gotSave.APIKey == nil || *store.gotSave.APIKey != "sk-fake-secret-0123456789" || *store.gotSave.Source != "own" {
		t.Fatalf("service got %+v", store.gotSave)
	}
}

func TestAISettingsHandler_Errors(t *testing.T) {
	store := &stubAIStore{}
	h := NewAISettingsHandler(store, validator.New(), logger.NewNop())

	for name, tc := range map[string]struct {
		body string
		err  error
		code int
		eCde string
	}{
		"unknown source":     {`{"source":"everyone"}`, nil, http.StatusBadRequest, ""},
		"bad json":           {`{`, nil, http.StatusBadRequest, ""},
		"not allowed":        {`{"source":"own"}`, tenantai.ErrOwnProviderNotAllowed, http.StatusForbidden, "AI_OWN_PROVIDER_NOT_ALLOWED"},
		"validation":         {`{"source":"own"}`, tenantai.ErrInvalid, http.StatusBadRequest, ""},
		"too long a URL":     {`{"base_url":"` + strings.Repeat("a", 600) + `"}`, nil, http.StatusBadRequest, ""},
		"internal is opaque": {`{"model":"m"}`, context.DeadlineExceeded, http.StatusInternalServerError, ""},
	} {
		t.Run(name, func(t *testing.T) {
			store.err = tc.err
			rec := httptest.NewRecorder()
			h.Update(rec, aiReq(http.MethodPut, tc.body))
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body)
			}
			if tc.eCde != "" {
				if code, _ := errorBody(t, rec); code != tc.eCde {
					t.Fatalf("code %q, want %q", code, tc.eCde)
				}
			}
			if strings.Contains(rec.Body.String(), "deadline") {
				t.Fatal("internal error text must not be returned")
			}
		})
	}
}

func TestAISettingsHandler_TestConnection(t *testing.T) {
	store := &stubAIStore{test: tenantai.TestResult{OK: false, Code: tenantai.TestBlockedAddress}}
	h := NewAISettingsHandler(store, validator.New(), logger.NewNop())

	// An empty body tests the stored configuration.
	rec := httptest.NewRecorder()
	h.Test(rec, aiReq(http.MethodPost, ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"code":"blocked_address"`) || !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	store.err = tenantai.ErrTooManyTests
	rec = httptest.NewRecorder()
	h.Test(rec, aiReq(http.MethodPost, `{}`))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}

	// No tenant in the context: refused before the service is called.
	store.gotTID = ""
	rec = httptest.NewRecorder()
	h.Test(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest || store.gotTID != "" {
		t.Fatalf("no tenant: status %d tid %q", rec.Code, store.gotTID)
	}
}
