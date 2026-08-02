package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
)

// TestFixApplied_RequiresFilter asserts the empty-filter guard: a fix-applied
// request with no cve_ids / asset_tags / asset_ids is rejected with 400 rather
// than silently matching every in_progress finding (the sibling "ids or filter
// required" guard, adapted to this filter-only action). The guard runs before
// any service/DB call, so a service built from nil repos is never exercised.
func TestFixApplied_RequiresFilter(t *testing.T) {
	svc := app.NewFindingActionsService(nil, nil, nil, nil, nil, nil, logger.NewNop())
	h := NewFindingActionsHandler(svc, logger.NewNop())

	cases := map[string]string{
		"empty filter object": `{"filter":{},"note":"done"}`,
		"missing filter":      `{"note":"done"}`,
		// asset_ids is the previously-dropped UI path — with only an empty
		// filter it must NOT fall through to a broad match.
		"empty arrays": `{"filter":{"cve_ids":[],"asset_tags":[],"asset_ids":[]},"note":"done"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/actions/fix-applied", strings.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "019d9095-a3fb-75dd-bc23-a244713dcc51"))
			rr := httptest.NewRecorder()

			h.FixApplied(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "required") {
				t.Errorf("expected 'required' in error body, got %s", rr.Body.String())
			}
		})
	}
}
