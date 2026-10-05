package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeFleetDaemons struct{ items map[string][]FleetItem }

func (f fakeFleetDaemons) FleetDaemons(_ context.Context, tenantID string) ([]FleetItem, error) {
	return f.items[tenantID], nil
}

type fakeFleetRunners struct{ items map[shared.ID][]FleetItem }

func (f fakeFleetRunners) FleetRunners(_ context.Context, tenantID shared.ID) ([]FleetItem, error) {
	return f.items[tenantID], nil
}

func fleetRequest(target string, tenant shared.ID, perms ...string) *http.Request {
	r := tenantRequest(http.MethodGet, target, "", tenant)
	return r.WithContext(context.WithValue(r.Context(), middleware.FetchedPermissionsKey, perms))
}

func decodeFleet(t *testing.T, w *httptest.ResponseRecorder) FleetListResponse {
	t.Helper()
	var out FleetListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return out
}

// Each mode is filtered by its own permission; a tenant sees only its own
// rows; a CI row is never offline; inactive rows are hidden by default.
func TestFleetList(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	now := time.Now()
	daemons := fakeFleetDaemons{items: map[string][]FleetItem{
		tenant.String(): {
			{ID: "d1", Mode: FleetModeDaemon, Kind: FleetKindSensor, Role: fleetRoleScanner, Name: "edge-1", Status: "online"},
			{ID: "d2", Mode: FleetModeDaemon, Kind: FleetKindSensor, Role: fleetRoleCollector, Name: "edge-2", Status: "offline", Attention: true},
			{ID: "d3", Mode: FleetModeDaemon, Kind: FleetKindSensor, Role: fleetRoleScanner, Name: "old", Status: "revoked", Inactive: true},
		},
		other.String(): {{ID: "x1", Mode: FleetModeDaemon, Name: "other-tenant-sensor", Status: "online"}},
	}}
	runners := fakeFleetRunners{items: map[shared.ID][]FleetItem{
		tenant: {
			{ID: "p1", Mode: FleetModeRunner, Kind: FleetKindCIPipeline, Role: fleetRoleScanner, Name: "github.com/acme/api", Status: "fresh", LastSeenAt: &now},
			{ID: "p2", Mode: FleetModeRunner, Kind: FleetKindCIPipeline, Role: fleetRoleScanner, Name: "github.com/acme/web", Status: "failing", Attention: true},
			{ID: "p3", Mode: FleetModeRunner, Kind: FleetKindCIPipeline, Role: fleetRoleScanner, Name: "github.com/acme/dead", Status: "archived", Inactive: true},
		},
		other: {{ID: "x2", Mode: FleetModeRunner, Name: "other-tenant-pipeline", Status: "fresh"}},
	}}
	scansOn := true
	h := NewFleetHandler(daemons, runners, func(context.Context, string, string) bool { return scansOn }, logger.NewNop())

	call := func(target string, tid shared.ID, perms ...string) (*httptest.ResponseRecorder, FleetListResponse) {
		w := httptest.NewRecorder()
		h.List(w, fleetRequest(target, tid, perms...))
		if w.Code != http.StatusOK {
			return w, FleetListResponse{}
		}
		return w, decodeFleet(t, w)
	}
	ids := func(out FleetListResponse) string {
		s := make([]string, 0, len(out.Data))
		for _, it := range out.Data {
			s = append(s, it.ID)
		}
		return strings.Join(s, ",")
	}

	// Both permissions: both modes, attention first, inactive hidden.
	_, out := call("/api/v1/fleet", tenant, "sensors:read", "scans:ci:read")
	if got := ids(out); got != "d2,p2,d1,p1" {
		t.Fatalf("all = %s", got)
	}
	if out.Counts[FleetModeDaemon].Total != 3 || out.Counts[FleetModeRunner].Total != 3 ||
		out.Counts[FleetModeRunner].ByStatus["failing"] != 1 || out.Counts[FleetModeRunner].Inactive != 1 {
		t.Fatalf("counts = %+v", out.Counts)
	}
	for _, it := range out.Data {
		if it.Mode == FleetModeRunner && it.Status == "offline" {
			t.Fatal("a CI row is offline")
		}
		if strings.HasPrefix(it.ID, "x") {
			t.Fatal("another tenant's row listed")
		}
	}
	// Inactive on request.
	if _, out = call("/api/v1/fleet?mode=runner&include_inactive=true", tenant, "scans:ci:read"); ids(out) != "p2,p1,p3" {
		t.Fatalf("include_inactive = %s", ids(out))
	}
	// Filters.
	if _, out = call("/api/v1/fleet?role=collector", tenant, "sensors:read", "scans:ci:read"); ids(out) != "d2" {
		t.Fatalf("role = %s", ids(out))
	}
	if _, out = call("/api/v1/fleet?status=archived,failing", tenant, "sensors:read", "scans:ci:read"); ids(out) != "p2,p3" {
		t.Fatalf("status = %s", ids(out))
	}
	if _, out = call("/api/v1/fleet?search=WEB", tenant, "sensors:read", "scans:ci:read"); ids(out) != "p2" {
		t.Fatalf("search = %s", ids(out))
	}
	if _, out = call("/api/v1/fleet?per_page=1&page=2", tenant, "sensors:read", "scans:ci:read"); ids(out) != "p2" || out.Total != 4 || out.TotalPages != 4 {
		t.Fatalf("paging = %s %d", ids(out), out.Total)
	}

	// sensors:read only: daemons only; asking for runners is forbidden.
	_, out = call("/api/v1/fleet", tenant, "sensors:read")
	if ids(out) != "d2,d1" || len(out.Modes) != 1 || out.Modes[0] != FleetModeDaemon {
		t.Fatalf("sensors:read only = %s %v", ids(out), out.Modes)
	}
	if _, ok := out.Counts[FleetModeRunner]; ok {
		t.Fatal("runner counts shown without scans:ci:read")
	}
	if w, _ := call("/api/v1/fleet?mode=runner", tenant, "sensors:read"); w.Code != http.StatusForbidden {
		t.Fatalf("runner mode without scans:ci:read: %d", w.Code)
	}
	// scans:ci:read only: runners only.
	if _, out = call("/api/v1/fleet", tenant, "scans:ci:read"); ids(out) != "p2,p1" {
		t.Fatalf("scans:ci:read only = %s", ids(out))
	}
	if w, _ := call("/api/v1/fleet?mode=daemon", tenant, "scans:ci:read"); w.Code != http.StatusForbidden {
		t.Fatalf("daemon mode without sensors:read: %d", w.Code)
	}
	// Scans module off: no runners even with the permission.
	scansOn = false
	if _, out = call("/api/v1/fleet", tenant, "sensors:read", "scans:ci:read"); ids(out) != "d2,d1" {
		t.Fatalf("scans module off = %s", ids(out))
	}
	if w, _ := call("/api/v1/fleet", tenant, "scans:ci:read"); w.Code != http.StatusForbidden {
		t.Fatalf("only CI read with the module off: %d", w.Code)
	}
	scansOn = true
	// Neither permission, bad mode or role.
	if w, _ := call("/api/v1/fleet", tenant, "findings:read"); w.Code != http.StatusForbidden {
		t.Fatalf("no permission: %d", w.Code)
	}
	if w, _ := call("/api/v1/fleet?mode=ci", tenant, "sensors:read"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", w.Code)
	}
	if w, _ := call("/api/v1/fleet?role=agent", tenant, "sensors:read"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad role: %d", w.Code)
	}
	// The other tenant sees only its own.
	if _, out = call("/api/v1/fleet", other, "sensors:read", "scans:ci:read"); ids(out) != "x2,x1" {
		t.Fatalf("other tenant = %s", ids(out))
	}
}

// fakePipelineService serves one pipeline of one tenant on one asset.
type fakePipelineService struct {
	CIPipelineService
	view cirunapp.PipelineView
}

func (f *fakePipelineService) GetPipeline(_ context.Context, tenantID, id shared.ID) (*cirunapp.PipelineView, error) {
	if f.view.TenantID != tenantID || f.view.ID != id {
		return nil, cirun.ErrPipelineNotFound
	}
	v := f.view
	return &v, nil
}

func (f *fakePipelineService) PipelineBranches(context.Context, shared.ID, shared.ID) ([]cirun.PipelineBranch, error) {
	return nil, nil
}

func (f *fakePipelineService) PipelineGateTrend(context.Context, shared.ID, shared.ID, int) ([]cirun.GatePoint, error) {
	return nil, nil
}

type denyAllScope struct{}

func (denyAllScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return nil, nil }
func (denyAllScope) AssertAsset(context.Context, shared.ID, shared.ID) error {
	return errors.New("out of scope")
}

// A pipeline of another tenant, or on a repository outside the caller's
// data scope, is not found.
func TestCIPipelineGetIsolation(t *testing.T) {
	tenant := shared.NewID()
	p := cirun.Pipeline{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: shared.NewID(), Provider: cirun.ProviderGitHub,
		RepositoryName: "github.com/acme/api", WorkflowPath: ".github/workflows/scan.yml"}
	svc := &fakePipelineService{view: cirunapp.PipelineView{Pipeline: p, Assessment: p.Assess(time.Now(), cirun.StatusPolicy{})}}
	get := func(h *CIAdminHandler, tid shared.ID) int {
		r := tenantRequest(http.MethodGet, "/api/v1/ci/pipelines/"+p.ID.String(), "", tid)
		r.SetPathValue("id", p.ID.String())
		w := httptest.NewRecorder()
		h.GetPipeline(w, r)
		return w.Code
	}
	h := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	h.SetPipelineService(svc)
	if code := get(h, tenant); code != http.StatusOK {
		t.Fatalf("own pipeline: %d", code)
	}
	if code := get(h, shared.NewID()); code != http.StatusNotFound {
		t.Fatalf("another tenant: %d", code)
	}
	scoped := NewCIAdminHandler(&fakeCIService{}, denyAllScope{}, logger.NewNop())
	scoped.SetPipelineService(svc)
	if code := get(scoped, tenant); code != http.StatusNotFound {
		t.Fatalf("out of data scope: %d", code)
	}
}
