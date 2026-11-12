package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// /findings/stats parses its filter exactly like the list endpoint (RFC-048):
// unknown values and oversized lists are rejected at the boundary with the
// same 400 INVALID_FILTER the list returns, before the service (nil here) is
// consulted.
func TestGetFindingStats_InvalidSourcesRejected(t *testing.T) {
	cases := map[string]string{
		"unknown source": "/api/v1/findings/stats?sources=sca,not-a-source",
		"too many":       "/api/v1/findings/stats?sources=" + repeatCSV("sca", 101),
		"bad severity":   "/api/v1/findings/stats?severity=urgent",
	}
	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			h := newEvidenceTestHandler()
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, "tenant-1"))
			rec := httptest.NewRecorder()

			h.GetFindingStats(rec, req)

			if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"code":"INVALID_FILTER"`) {
				t.Fatalf("want 400 INVALID_FILTER, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func repeatCSV(v string, n int) string {
	out := v
	for i := 1; i < n; i++ {
		out += "," + v
	}
	return out
}
