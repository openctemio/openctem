package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Asking to override a scan freeze window without scans:freeze:override is
// refused before the scan service is reached (the handler has none here: a
// call through would panic).
func TestTriggerScan_FreezeOverrideNeedsPermission(t *testing.T) {
	h := NewScanHandler(nil, nil, nil, nil, logger.NewNop())
	ctx := context.WithValue(context.Background(), middleware.IsAdminKey, false)
	ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, []string{"scans:read", "scans:execute"})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "01a10d6a-fb64-7112-82ee-08cd5b3d371e")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/x/trigger", strings.NewReader(`{"override_freeze": true}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.TriggerScan(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an override without scans:freeze:override", rec.Code)
	}
}
