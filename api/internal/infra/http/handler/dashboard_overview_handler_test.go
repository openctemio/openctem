package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// The overview answers each dashboard read by sending it through the API's
// own router with the caller's credentials, so each part keeps its
// endpoint's gates. These tests use a fake router that records what reaches
// it and answers like gated endpoints.
func TestDashboardOverview_DispatchesOnlyTheAllowlistWithTheCallersCredentials(t *testing.T) {
	var (
		mu   sync.Mutex
		seen = map[string]http.Header{}
	)
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.RequestURI()] = r.Header.Clone()
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/attack-surface/attack-paths":
			// A gate refusing the caller: status only, no body passed on.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"FORBIDDEN"}`))
		case "/api/v1/scans/coverage":
			// Not JSON: never passed on.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello"))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
		}
	})
	h := NewDashboardOverviewHandler(func() http.Handler { return router }, logger.NewNop())

	// Query parameters of the overview request choose nothing.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?path=/api/v1/admin/x", nil)
	req.Header.Set("Cookie", "auth_token=abc")
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec := httptest.NewRecorder()
	h.Overview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
	var resp DashboardOverviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(DashboardOverviewParts) || len(resp.Parts) != len(DashboardOverviewParts) {
		t.Fatalf("dispatched %d, answered %d, want %d", len(seen), len(resp.Parts), len(DashboardOverviewParts))
	}
	for _, part := range DashboardOverviewParts {
		hdr, ok := seen[part]
		if !ok {
			t.Fatalf("part %s not dispatched", part)
		}
		if hdr.Get("Cookie") != "auth_token=abc" || hdr.Get("Authorization") != "Bearer tok" {
			t.Errorf("%s: credentials not forwarded: %v", part, hdr)
		}
		if hdr.Get("X-Forwarded-For") != "" {
			t.Errorf("%s: forwarded a client header it should not", part)
		}
	}
	for uri := range seen {
		if strings.Contains(uri, "admin") {
			t.Fatalf("dispatched a path from the request: %s", uri)
		}
	}
	if p := resp.Parts["/api/v1/attack-surface/attack-paths"]; p.Status != http.StatusForbidden || len(p.Body) != 0 {
		t.Errorf("a refused part must carry its status and no body: %+v", p)
	}
	if p := resp.Parts["/api/v1/scans/coverage"]; len(p.Body) != 0 {
		t.Errorf("a non-JSON part must carry no body: %+v", p)
	}
	if p := resp.Parts["/api/v1/dashboard/stats"]; p.Status != http.StatusOK || !strings.Contains(string(p.Body), "/api/v1/dashboard/stats") {
		t.Errorf("an allowed part must carry its body: %+v", p)
	}
}
