package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A refused retest reaches the console as a registered code with the retest
// reason code in details, never as the raw sensor or service text only.
func TestFindingRetestWriteError_TypedCodes(t *testing.T) {
	h := &FindingRetestHandler{logger: logger.NewNop()}
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		reason string
	}{
		{"no template sensor", fmt.Errorf("queue: %w", retestdom.ErrNoTemplateSensor), http.StatusUnprocessableEntity, "RETEST_NO_TEMPLATE_SENSOR", retestapp.ReasonNoTemplateSensor},
		{"no sensor", retestdom.ErrNoSensor, http.StatusUnprocessableEntity, "RETEST_NO_SENSOR", retestapp.ReasonNoSensor},
		{"no check sensor", retestdom.ErrNoCheckSensor, http.StatusUnprocessableEntity, "RETEST_NO_CHECK_SENSOR", retestapp.ReasonNoCheckSensor},
		{"not eligible without a code", retestdom.ErrNotEligible, http.StatusUnprocessableEntity, "RETEST_NOT_AVAILABLE", retestapp.ReasonNotEligible},
		{"rate limited", retestdom.ErrRateLimited, http.StatusTooManyRequests, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.writeError(rec, tc.err)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if tc.code == "" {
				return
			}
			var body struct {
				Code    string         `json:"code"`
				Details map[string]any `json:"details"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tc.code || body.Details["reason"] != tc.reason {
				t.Fatalf("body %+v, want %s reason %s", body, tc.code, tc.reason)
			}
		})
	}
}

// An unknown mode is refused before the service is called.
func TestFindingRetestRequest_RefusesUnknownMode(t *testing.T) {
	h := &FindingRetestHandler{logger: logger.NewNop()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/x/retests", strings.NewReader(`{"mode":"exploit"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", shared.NewID().String())
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	req = req.WithContext(context.WithValue(ctx, middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.Request(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}
