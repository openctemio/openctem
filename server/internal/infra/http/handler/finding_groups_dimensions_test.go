package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The groups endpoint accepts exactly the dimensions the repository groups by.
func TestFindingGroupByDimensions_MatchRepository(t *testing.T) {
	want := []string{"cve_id", "rule_id", "asset_id", "owner_id", "component_id", "severity", "source", "finding_type", "family"}
	if len(findingGroupByDimensions) != len(want) {
		t.Fatalf("got %d dimensions, want %d", len(findingGroupByDimensions), len(want))
	}
	for _, d := range want {
		if !findingGroupByDimensions[d] {
			t.Errorf("dimension %q is not accepted", d)
		}
	}
}

// Values the repository cannot group by are rejected before any service call
// ("status" and "type" used to pass and fail in the repository with a 500).
func TestListFindingGroups_RejectsUnknownDimension(t *testing.T) {
	svc := finding.NewFindingActionsService(nil, nil, nil, nil, nil, nil, logger.NewNop())
	h := NewFindingActionsHandler(svc, logger.NewNop())

	for _, dim := range []string{"status", "type", "assignee", "cve_id OR 1=1"} {
		t.Run(dim, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/groups?group_by="+url.QueryEscape(dim), nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "019d9095-a3fb-75dd-bc23-a244713dcc51"))
			rr := httptest.NewRecorder()
			h.ListFindingGroups(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
			}
		})
	}
}
