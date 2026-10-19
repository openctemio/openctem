package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// "AI is not available here" is never answered as "you have no permission":
// each reason has its own code, so the web UI can show the reason and where
// to fix it. Internal error text is never in the body.
func TestAITriageHandler_ErrorCodes(t *testing.T) {
	h := &AITriageHandler{logger: logger.NewNop()}
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{aitriage.ErrPlatformAINotSetUp, http.StatusServiceUnavailable, "AI_PLATFORM_NOT_CONFIGURED"},
		{aitriage.ErrAIDisabled, http.StatusForbidden, "AI_DISABLED"},
		{fmt.Errorf("%w: campaign_tlp_above_limit", aitriage.ErrPolicyRestricted), http.StatusForbidden, "AI_POLICY_RESTRICTED"},
		{fmt.Errorf("%w: busy", aitriagedom.ErrDuplicateRequest), http.StatusConflict, "CONFLICT"},
		{fmt.Errorf("failed to get finding: %w", shared.ErrNotFound), http.StatusNotFound, "NOT_FOUND"},
		{fmt.Errorf("%w: data scope", shared.ErrForbidden), http.StatusForbidden, "FORBIDDEN"},
		{fmt.Errorf("pq: connection to 10.0.0.5 refused"), http.StatusInternalServerError, "INTERNAL_ERROR"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, tc.err)
		code, msg := errorBody(t, rec)
		if rec.Code != tc.status || code != tc.code || msg == "" {
			t.Errorf("%v: status=%d code=%q message=%q, want %d %s", tc.err, rec.Code, code, msg, tc.status, tc.code)
		}
		if strings.Contains(rec.Body.String(), "10.0.0.5") || strings.Contains(rec.Body.String(), "campaign_tlp") {
			t.Errorf("%v: internal detail leaked: %s", tc.err, rec.Body.String())
		}
	}
}

// A bulk request counts each finding toward the tenant's AI triage rate
// limit: past the allowance it is refused before anything is queued.
func TestAITriageHandler_BulkCountsEachFinding(t *testing.T) {
	svc := aitriage.NewAITriageService(nil, nil, nil, nil, nil, config.AITriageConfig{}, logger.NewNop())
	h := NewAITriageHandler(svc, logger.NewNop())
	var asked int
	h.SetBulkAllowance(func(tenantID string, n int) bool {
		asked = n
		return n <= 4
	})
	ids := make([]string, 12)
	for i := range ids {
		ids[i] = shared.NewID().String()
	}
	body, _ := json.Marshal(map[string]any{"finding_ids": ids})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/ai-triage/bulk", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.RequestBulkTriage(rec, req)
	if rec.Code != http.StatusTooManyRequests || asked != 11 {
		t.Fatalf("status=%d asked=%d, want 429 after asking for 11 more units", rec.Code, asked)
	}
}
