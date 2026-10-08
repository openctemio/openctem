package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	testRunID    = "01a0f6e2-35a7-7cae-af10-874c1481fe6e"
	testTenantID = "01a0f6e2-35a7-7cae-af10-874c1481fe6f"
)

// serveScanWorkflowRoutes mounts the scan workflow and scan run routes for a
// caller holding perms. A nil service makes the handler panic once the gates
// let a request through, which is how "reached the handler" is observed.
func serveScanWorkflowRoutes(t *testing.T, perms []string, method, path string) (code int, reached bool) {
	t.Helper()
	router := infrahttp.NewChiRouter()
	as := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.IsAdminKey, false)
			ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
			ctx = context.WithValue(ctx, middleware.TenantIDKey, testTenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	registerScanWorkflowRoutes(router, handler.NewScanWorkflowHandler(nil, nil, logger.NewNop()), as, nil, nil)
	mux := router.(interface{ Handler() http.Handler }).Handler()
	defer func() {
		if recover() != nil {
			reached = true
		}
	}()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code, false
}

// A scan run is one execution of a Scan: reading it needs scans:read and
// stopping it needs scans:write. The scan workflow permissions (the graph
// editor) grant neither.
func TestScanRunRoutes_FollowScanPermissions(t *testing.T) {
	read := []string{
		"/api/v1/scan-runs/",
		"/api/v1/scan-runs/" + testRunID,
		"/api/v1/scan-runs/" + testRunID + "/tasks",
		"/api/v1/scan-runs/" + testRunID + "/stages",
		"/api/v1/scan-runs/" + testRunID + "/map",
		"/api/v1/scan-runs/" + testRunID + "/outputs?step_key=ports",
	}
	for _, path := range read {
		if code, reached := serveScanWorkflowRoutes(t, []string{permission.ScanWorkflowsRead.String(), permission.ScanWorkflowsWrite.String()}, http.MethodGet, path); reached || code != http.StatusForbidden {
			t.Errorf("GET %s with scans:workflows:* only: code=%d reached=%v, want 403", path, code, reached)
		}
		if _, reached := serveScanWorkflowRoutes(t, []string{permission.ScansRead.String()}, http.MethodGet, path); !reached {
			t.Errorf("GET %s with scans:read: did not reach the handler", path)
		}
	}

	cancel := "/api/v1/scan-runs/" + testRunID + "/cancel"
	if code, reached := serveScanWorkflowRoutes(t, []string{permission.ScansRead.String(), permission.ScanWorkflowsWrite.String()}, http.MethodPost, cancel); reached || code != http.StatusForbidden {
		t.Errorf("cancel without scans:write: code=%d reached=%v, want 403", code, reached)
	}
	if _, reached := serveScanWorkflowRoutes(t, []string{permission.ScansWrite.String()}, http.MethodPost, cancel); !reached {
		t.Error("cancel with scans:write: did not reach the handler")
	}
}

// The workflow editor needs scans:workflows:*; scans:read and scans:write
// (running scans) do not let a caller read or change a workflow graph.
func TestScanWorkflowRoutes_NeedWorkflowPermissions(t *testing.T) {
	const wf = "/api/v1/scan-workflows/" + testRunID
	for _, rt := range []struct {
		method, path string
		perm         permission.Permission
	}{
		{http.MethodGet, "/api/v1/scan-workflows/", permission.ScanWorkflowsRead},
		{http.MethodGet, wf, permission.ScanWorkflowsRead},
		{http.MethodPost, "/api/v1/scan-workflows/", permission.ScanWorkflowsWrite},
		{http.MethodPut, wf, permission.ScanWorkflowsWrite},
		{http.MethodPost, "/api/v1/scan-workflows/verify", permission.ScanWorkflowsWrite},
		{http.MethodPost, wf + "/clone", permission.ScanWorkflowsWrite},
		{http.MethodDelete, wf, permission.ScanWorkflowsDelete},
		{http.MethodDelete, wf + "/steps/s1", permission.ScanWorkflowsDelete},
	} {
		if code, reached := serveScanWorkflowRoutes(t, []string{permission.ScansRead.String(), permission.ScansWrite.String()}, rt.method, rt.path); reached || code != http.StatusForbidden {
			t.Errorf("%s %s with scans:read+write: code=%d reached=%v, want 403", rt.method, rt.path, code, reached)
		}
		// The handler either panics on its nil service or refuses the empty
		// body itself; either way the permission gate let the request in.
		if code, reached := serveScanWorkflowRoutes(t, []string{rt.perm.String()}, rt.method, rt.path); !reached && code == http.StatusForbidden {
			t.Errorf("%s %s with %s: 403, want the gate to pass", rt.method, rt.path, rt.perm)
		}
	}
}

// The renamed paths have no aliases, and a run is started only by triggering
// a Scan: the old paths and the direct workflow run are gone (404/405), for a
// caller holding every scan permission.
func TestScanWorkflowRoutes_OldPathsAreGone(t *testing.T) {
	all := []string{
		permission.ScansRead.String(), permission.ScansWrite.String(),
		permission.ScanWorkflowsRead.String(), permission.ScanWorkflowsWrite.String(), permission.ScanWorkflowsDelete.String(),
	}
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/pipelines/"},
		{http.MethodGet, "/api/v1/pipelines/" + testRunID},
		{http.MethodPost, "/api/v1/pipelines/" + testRunID + "/runs"},
		{http.MethodGet, "/api/v1/pipeline-runs/"},
		{http.MethodGet, "/api/v1/pipeline-runs/" + testRunID},
		{http.MethodPost, "/api/v1/pipeline-runs/" + testRunID + "/cancel"},
		{http.MethodPost, "/api/v1/scan-workflows/" + testRunID + "/runs"},
		{http.MethodGet, "/api/v1/scan-workflows/" + testRunID + "/runs"},
	} {
		code, reached := serveScanWorkflowRoutes(t, all, rt.method, rt.path)
		if reached || (code != http.StatusNotFound && code != http.StatusMethodNotAllowed) {
			t.Errorf("%s %s: code=%d reached=%v, want 404 or 405", rt.method, rt.path, code, reached)
		}
	}
}
