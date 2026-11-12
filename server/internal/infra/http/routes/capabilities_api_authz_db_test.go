package routes

// The one capability resource (/api/v1/capabilities): platform capabilities
// and the organization's own custom ones. Every refusal is checked against
// the real registration and database: a member and a viewer cannot change
// custom capabilities (scans:tools:write/delete, owner and admin), another
// tenant's custom capability and the platform capabilities are not found for
// every verb (never a 403 that would confirm an id), and include=usage passes
// the shared include= conformance suite.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	capabilityapp "github.com/openctemio/openctem/api/internal/app/capability"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/include/includetest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newCapabilityHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	svc := capabilityapp.NewCapabilityService(postgres.NewCapabilityRepository(db),
		auditapp.NewAuditService(postgres.NewAuditRepository(db), log), log)

	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Capability: handler.NewCapabilityHandler(svc, validator.New(), log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantapp.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

func cleanupCapabilities(t *testing.T, h *authzPolicyHarness, tenants ...string) {
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM capabilities WHERE tenant_id = ANY($1::uuid[])`,
			"{"+strings.Join(tenants, ",")+"}")
	})
}

func capabilityNames(t *testing.T, body string) map[string]handler.CapabilityResponse {
	t.Helper()
	var resp handler.CapabilityListResponse
	mustJSON(t, body, &resp)
	out := make(map[string]handler.CapabilityResponse, len(resp.Items))
	for _, it := range resp.Items {
		out[it.Name] = it
	}
	return out
}

func TestCapabilitiesAPI_Authorization_DB(t *testing.T) {
	h := newCapabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, member, viewer := h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	otherAdmin := h.member(other, "admin")
	cleanupCapabilities(t, h, tid, other)

	var platformID string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT id FROM capabilities WHERE tenant_id IS NULL AND name = 'sast'`).Scan(&platformID); err != nil {
		t.Fatal(err)
	}
	const create = `{"name":"zz-authz-cap","display_name":"Ours","category":"security"}`
	const update = `{"display_name":"Changed"}`

	// Custom capabilities: owner and admin only (scans:tools:write/delete).
	h.expect(member, http.MethodPost, "/api/v1/capabilities", create, http.StatusForbidden)
	h.expect(viewer, http.MethodPost, "/api/v1/capabilities", create, http.StatusForbidden)
	ours := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/capabilities", create, http.StatusCreated))
	theirs := decodeID(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/capabilities",
		`{"name":"zz-their-cap","display_name":"Theirs"}`, http.StatusCreated))
	h.expect(member, http.MethodPut, "/api/v1/capabilities/"+ours, update, http.StatusForbidden)
	h.expect(member, http.MethodDelete, "/api/v1/capabilities/"+ours, "", http.StatusForbidden)
	h.expect(viewer, http.MethodDelete, "/api/v1/capabilities/"+ours, "", http.StatusForbidden)

	// A platform capability and another tenant's custom one: not found, for
	// every verb, even for an administrator.
	for _, id := range []string{platformID, theirs} {
		h.expect(admin, http.MethodPut, "/api/v1/capabilities/"+id, update, http.StatusNotFound)
		h.expect(admin, http.MethodDelete, "/api/v1/capabilities/"+id+"?force=true", "", http.StatusNotFound)
	}
	h.expect(admin, http.MethodGet, "/api/v1/capabilities/"+theirs, "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/capabilities/"+theirs+"?include=usage", "", http.StatusNotFound)
	for _, id := range []string{platformID, theirs} {
		var name string
		if err := h.db.QueryRowContext(context.Background(), `SELECT display_name FROM capabilities WHERE id = $1`, id).Scan(&name); err != nil || name == "Changed" {
			t.Fatalf("capability %s after the refused changes: %q (%v)", id, name, err)
		}
	}

	// The view: platform plus our own, never theirs; source filters.
	all := capabilityNames(t, h.expect(viewer, http.MethodGet, "/api/v1/capabilities?per_page=100", "", http.StatusOK))
	if all["zz-authz-cap"].Source != "custom" || all["sast"].Source != "platform" {
		t.Fatalf("view: ours %+v, sast %+v", all["zz-authz-cap"], all["sast"])
	}
	if _, leaked := all["zz-their-cap"]; leaked {
		t.Fatal("another tenant's custom capability is listed")
	}
	custom := capabilityNames(t, h.expect(viewer, http.MethodGet, "/api/v1/capabilities?source=custom", "", http.StatusOK))
	if len(custom) != 1 {
		t.Fatalf("source=custom: %v", custom)
	}
	platform := capabilityNames(t, h.expect(viewer, http.MethodGet, "/api/v1/capabilities?source=platform&per_page=100", "", http.StatusOK))
	if _, ok := platform["zz-authz-cap"]; ok || len(platform) == 0 {
		t.Fatalf("source=platform lists %d, ours included: %v", len(platform), ok)
	}
	byCat := capabilityNames(t, h.expect(viewer, http.MethodGet, "/api/v1/capabilities?category=security&per_page=100", "", http.StatusOK))
	for name, c := range byCat {
		if c.Category != "security" {
			t.Fatalf("category=security lists %s (%s)", name, c.Category)
		}
	}
	long := strings.Repeat("a", 256)
	for _, q := range []string{"source=everyone", "include=secrets", "include=usage.tools", "q=" + long, "category=" + long[:51]} {
		h.expect(viewer, http.MethodGet, "/api/v1/capabilities?"+q, "", http.StatusBadRequest)
	}

	// The catalog read is needed; usage also needs the tenant's tools read.
	noCatalog := h.member(tid, "member")
	h.customRoleMember(noCatalog, tid, permission.TenantToolsRead)
	h.mintToken(&noCatalog, tid)
	h.expect(noCatalog, http.MethodGet, "/api/v1/capabilities", "", http.StatusForbidden)

	h.expect(admin, http.MethodPut, "/api/v1/capabilities/"+ours, update, http.StatusOK)
	h.expect(admin, http.MethodDelete, "/api/v1/capabilities/"+ours, "", http.StatusNoContent)
	h.expect(admin, http.MethodGet, "/api/v1/capabilities/"+ours, "", http.StatusNotFound)
}

// include=usage: the shared suite, then sensor names only with sensors:read.
func TestCapabilitiesAPI_IncludeConformance_DB(t *testing.T) {
	h := newCapabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, otherAdmin := h.member(tid, "admin"), h.member(other, "admin")
	cleanupCapabilities(t, h, tid, other)
	// bare: the catalog read only.
	bare := h.member(tid, "member")
	h.customRoleMember(bare, tid, permission.ToolsRead)
	h.mintToken(&bare, tid)

	ours := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/capabilities",
		`{"name":"zz-incl-cap","display_name":"Ours"}`, http.StatusCreated))
	theirs := decodeID(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/capabilities",
		`{"name":"zz-incl-their-cap","display_name":"Theirs"}`, http.StatusCreated))

	includetest.RunConformance(t, includetest.Fixture{
		Registry: handler.CapabilityIncludes,
		Get: func(t *testing.T, principal, path string) (int, http.Header, string) {
			u := admin
			if principal == includetest.Bare {
				u = bare
			}
			return h.doWithHeaders(u, http.MethodGet, path)
		},
		ListPath:        "/api/v1/capabilities",
		ItemPath:        "/api/v1/capabilities/" + ours,
		ForeignItemPath: "/api/v1/capabilities/" + theirs,
		ItemsKey:        "items",
		AllowedKeys: map[string][]string{
			"usage": {"tool_count", "sensor_count", "tool_names", "sensor_names"},
		},
	})

	// A sensor of ours with the capability: named only with sensors:read;
	// another tenant's sensor is never counted.
	h.sensorWithCapability(tid, "zz-incl-sensor", "zz-incl-cap")
	h.sensorWithCapability(other, "zz-their-sensor", "zz-incl-cap")
	toolsOnly := h.member(tid, "member")
	h.customRoleMember(toolsOnly, tid, permission.ToolsRead, permission.TenantToolsRead)
	h.mintToken(&toolsOnly, tid)
	var one handler.CapabilityResponse
	mustJSON(t, h.expect(toolsOnly, http.MethodGet, "/api/v1/capabilities/"+ours+"?include=usage", "", http.StatusOK), &one)
	if one.Usage == nil || one.Usage.SensorCount != 1 || len(one.Usage.SensorNames) != 0 {
		t.Fatalf("without sensors:read: %+v", one.Usage)
	}
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/capabilities/"+ours+"?include=usage", "", http.StatusOK), &one)
	if one.Usage == nil || one.Usage.SensorCount != 1 || len(one.Usage.SensorNames) != 1 || one.Usage.SensorNames[0] != "zz-incl-sensor" {
		t.Fatalf("with sensors:read: %+v", one.Usage)
	}
}

// sensorWithCapability inserts a sensor of tenantID reporting capability.
func (h *authzPolicyHarness) sensorWithCapability(tenantID, name, capability string) {
	h.t.Helper()
	id := h.sensor(tenantID)
	h.exec(`UPDATE sensors SET name = $2, capabilities = ARRAY[$3]::text[] WHERE id = $1`, id, name, capability)
}

// The routes the one capability resource replaced are gone.
func TestCapabilitiesAPI_RemovedRoutes_DB(t *testing.T) {
	h := newCapabilityHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")
	id := "00000000-0000-0000-0000-0000000000aa"
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/capabilities/by-category/security"},
		{http.MethodPost, "/api/v1/capabilities/usage-stats"},
		{http.MethodGet, "/api/v1/capabilities/" + id + "/usage-stats"},
		{http.MethodPost, "/api/v1/custom-capabilities"},
		{http.MethodPut, "/api/v1/custom-capabilities/" + id},
		{http.MethodDelete, "/api/v1/custom-capabilities/" + id},
	} {
		code, body := h.do(admin, rt.method, rt.path, `{"ids":["`+id+`"]}`)
		if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d, want gone: %s", rt.method, rt.path, code, body)
		}
	}
	// /all now names an id: a malformed one, refused before any lookup.
	if code, _ := h.do(admin, http.MethodGet, "/api/v1/capabilities/all", ""); code != http.StatusBadRequest {
		t.Errorf("GET /capabilities/all: %d, want 400 (an invalid id)", code)
	}
}
