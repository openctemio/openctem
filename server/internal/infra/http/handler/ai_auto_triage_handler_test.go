package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type stubAutoTriageStore struct {
	stubAIStore
	saveErr error
	gotTID  string
	got     tenant.AutoTriagePolicy
	calls   int
}

func (s *stubAutoTriageStore) GetAutoTriage(_ context.Context, tid string) (tenant.AutoTriagePolicy, error) {
	s.gotTID = tid
	return tenant.AutoTriagePolicy{Enabled: true, Severities: []string{"critical"}, DelaySeconds: 60}, nil
}

func (s *stubAutoTriageStore) SaveAutoTriage(_ context.Context, tid string, in tenant.AutoTriagePolicy, _ auditapp.AuditContext) (tenantai.AutoTriageView, error) {
	s.calls++
	s.gotTID, s.got = tid, in
	if s.saveErr != nil {
		return tenantai.AutoTriageView{}, s.saveErr
	}
	return tenantai.AutoTriageView{AutoTriagePolicy: in, Loosened: true}, nil
}

// The automatic triage routes: the organization comes from the context
// (never the body), a service step-up refusal is answered 403
// STEP_UP_REQUIRED, invalid severities and delays never reach the service.
func TestAIAutoTriageHandler(t *testing.T) {
	store := &stubAutoTriageStore{}
	h := NewAISettingsHandler(store, validator.New(), logger.NewNop())

	rec := httptest.NewRecorder()
	h.GetAutoTriage(rec, aiReq(http.MethodGet, ""))
	if rec.Code != http.StatusOK || store.gotTID != "11111111-1111-7111-8111-111111111111" {
		t.Fatalf("get: %d %s tenant %q", rec.Code, rec.Body, store.gotTID)
	}

	rec = httptest.NewRecorder()
	h.UpdateAutoTriage(rec, aiReq(http.MethodPut, `{"enabled":true,"severities":["critical","high"],"delay_seconds":30,"tenant_id":"22222222-2222-7222-8222-222222222222"}`))
	var resp AIAutoTriageResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.Loosened || len(resp.Severities) != 2 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if store.gotTID != "11111111-1111-7111-8111-111111111111" {
		t.Fatalf("the organization must come from the context, got %q", store.gotTID)
	}

	store.saveErr = fmt.Errorf("widen: %w", middleware.ErrStepUpRequired)
	rec = httptest.NewRecorder()
	h.UpdateAutoTriage(rec, aiReq(http.MethodPut, `{"enabled":true,"severities":["critical"]}`))
	if rec.Code != http.StatusForbidden || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("step-up refusal: %d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if fmt.Sprint(body["code"]) != string(middleware.CodeStepUpRequired) {
		t.Fatalf("step-up refusal code: %s", rec.Body)
	}

	store.saveErr, store.calls = nil, 0
	for _, bad := range []string{`{"severities":["urgent"]}`, `{"delay_seconds":-1}`, `{"delay_seconds":3601}`, `not json`} {
		rec = httptest.NewRecorder()
		h.UpdateAutoTriage(rec, aiReq(http.MethodPut, bad))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
	if store.calls != 0 {
		t.Fatalf("invalid input reached the service %d times", store.calls)
	}

	// A store without the policy (an older build): 404, not a panic.
	rec = httptest.NewRecorder()
	NewAISettingsHandler(&stubAIStore{}, validator.New(), logger.NewNop()).GetAutoTriage(rec, aiReq(http.MethodGet, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("store without the policy: %d", rec.Code)
	}
}
