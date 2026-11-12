package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	codescanapp "github.com/openctemio/openctem/api/internal/app/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCodeScan struct {
	calls []string
	scope *shared.DataScope
}

func (f *fakeCodeScan) status(id shared.ID) *codescanapp.RepositoryStatus {
	return &codescanapp.RepositoryStatus{Repository: codescan.RepositoryRef{AssetID: id, Name: "acme/api"},
		Settings: codescan.Defaults(shared.NewID()), Source: codescan.SourceDefault}
}
func (f *fakeCodeScan) Template(context.Context, shared.ID) (codescan.Settings, string, error) {
	f.calls = append(f.calls, "template")
	return codescan.Defaults(shared.NewID()), codescan.SourceDefault, nil
}
func (f *fakeCodeScan) UpdateTemplate(_ context.Context, _ shared.ID, in codescanapp.SettingsInput, _ codescanapp.Actor) (codescan.Settings, error) {
	f.calls = append(f.calls, "update-template")
	s := codescan.Settings{ProtectedBranches: in.ProtectedBranches, Capabilities: in.Capabilities, Schedule: in.Schedule, Routing: in.Routing}
	return s, s.Validate()
}
func (f *fakeCodeScan) Repository(_ context.Context, _, id shared.ID) (*codescanapp.RepositoryStatus, error) {
	f.calls = append(f.calls, "get")
	return f.status(id), nil
}
func (f *fakeCodeScan) ListRepositories(_ context.Context, _ shared.ID, scope *shared.DataScope, _, _ int) ([]codescanapp.RepositoryStatus, int, error) {
	f.calls = append(f.calls, "list")
	f.scope = scope
	return nil, 0, nil
}
func (f *fakeCodeScan) UpdateRepository(_ context.Context, _, id shared.ID, _ codescanapp.SettingsInput, _ codescanapp.Actor) (*codescanapp.RepositoryStatus, error) {
	f.calls = append(f.calls, "update")
	return f.status(id), nil
}
func (f *fakeCodeScan) ResetRepository(_ context.Context, _, id shared.ID, _ codescanapp.Actor) (*codescanapp.RepositoryStatus, error) {
	f.calls = append(f.calls, "reset")
	return f.status(id), nil
}
func (f *fakeCodeScan) Rebaseline(_ context.Context, _, id shared.ID, _ codescanapp.Actor) (int, *codescanapp.RepositoryStatus, error) {
	f.calls = append(f.calls, "rebaseline")
	return 1, f.status(id), nil
}

const codeScanBody = `{"protected_branches":["{default}","release/*"],"capabilities":["sast","secrets"],"schedule":"weekly","routing":"auto","enabled":true}`

// A repository outside the caller's data scope is 404 on every by-id route,
// and the service is never called.
func TestCodeScanRepositoryRoutesHonorDataScope(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	routes := map[string]func(*CIAdminHandler) http.HandlerFunc{
		"get":        func(h *CIAdminHandler) http.HandlerFunc { return h.GetCodeScanRepository },
		"update":     func(h *CIAdminHandler) http.HandlerFunc { return h.UpdateCodeScanRepository },
		"reset":      func(h *CIAdminHandler) http.HandlerFunc { return h.ResetCodeScanRepository },
		"rebaseline": func(h *CIAdminHandler) http.HandlerFunc { return h.RebaselineCodeScanRepository },
	}
	for name, route := range routes {
		svc := &fakeCodeScan{}
		h := NewCIAdminHandler(nil, denyScope{}, logger.NewNop())
		h.SetCodeScanService(svc)
		r := tenantRequest(http.MethodPut, "/", codeScanBody, tenant)
		r.SetPathValue("id", asset.String())
		w := httptest.NewRecorder()
		route(h)(w, r)
		if w.Code != http.StatusNotFound || len(svc.calls) != 0 {
			t.Errorf("%s out of scope: %d, calls %v", name, w.Code, svc.calls)
		}

		h = NewCIAdminHandler(nil, nil, logger.NewNop())
		h.SetCodeScanService(svc)
		r = tenantRequest(http.MethodPut, "/", codeScanBody, tenant)
		r.SetPathValue("id", asset.String())
		w = httptest.NewRecorder()
		route(h)(w, r)
		if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
			t.Errorf("%s in scope: %d %s", name, w.Code, w.Body.String())
		}
	}
}

func TestCodeScanTemplateAndList(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeCodeScan{}
	h := NewCIAdminHandler(nil, nil, logger.NewNop())
	h.SetCodeScanService(svc)

	w := httptest.NewRecorder()
	h.UpdateCodeScanTemplate(w, tenantRequest(http.MethodPut, "/", codeScanBody, tenant))
	var got CodeScanSettingsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Source != codescan.SourceTemplate || len(got.ProtectedBranches) != 2 {
		t.Fatalf("update template: %d %s", w.Code, w.Body.String())
	}
	// Unknown fields and invalid values are refused.
	w = httptest.NewRecorder()
	h.UpdateCodeScanTemplate(w, tenantRequest(http.MethodPut, "/", `{"protected_branches":["main"],"capabilities":["sast"],"schedule":"weekly","routing":"auto","enabled":true,"tenant_id":"x"}`, tenant))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.UpdateCodeScanTemplate(w, tenantRequest(http.MethodPut, "/", `{"protected_branches":["--all"],"capabilities":["sast"],"schedule":"weekly","routing":"auto"}`, tenant))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid branch: %d", w.Code)
	}

	// The list carries the caller's data scope to the service.
	scoped := NewCIAdminHandler(nil, denyScope{}, logger.NewNop())
	scoped.SetCodeScanService(svc)
	w = httptest.NewRecorder()
	scoped.ListCodeScanRepositories(w, tenantRequest(http.MethodGet, "/api/v1/ci/code-scanning/repositories", "", tenant))
	if w.Code != http.StatusOK || svc.scope == nil {
		t.Fatalf("list: %d scope %v", w.Code, svc.scope)
	}

	// Without the service wired: 404, not a panic.
	bare := NewCIAdminHandler(nil, nil, logger.NewNop())
	w = httptest.NewRecorder()
	bare.GetCodeScanTemplate(w, tenantRequest(http.MethodGet, "/", "", tenant))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired: %d", w.Code)
	}
}
