package routes

// Organization tool defaults end to end (docs/architecture/sensors.md, "Tool
// settings"): every member reads them, only owners and administrators save
// and reset; they are validated against every schema the organization's
// sensors report; a sensor overrides a key in either direction; the claim
// delivers them only to the organization's own sensors (never a platform
// sensor, never another organization's); a scan may only lower them; an
// Impact change needs step-up; every change is audited.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// layeredToolConfig: a narrowing scan-scope option (retries), a sensor-only
// key (workers) and an Impact (T1) switch.
const layeredToolConfig = `{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{` +
	`"retries":{"type":"integer","minimum":0,"maximum":5,"default":1,"x-octm-common":"retries","x-octm-flag":"-retries","x-octm-scope":"scan"},` +
	`"workers":{"type":"integer","minimum":1,"maximum":200,"default":25,"x-octm-flag":"-w","x-octm-scope":"sensor"},` +
	`"follow_redirects":{"type":"boolean","default":false,"x-octm-tier":"T1","x-octm-flag":"-fr","x-octm-scope":"sensor"}}}`

func effectiveByKey(items []handler.EffectiveToolSettingResponse) map[string]handler.EffectiveToolSettingResponse {
	out := map[string]handler.EffectiveToolSettingResponse{}
	for _, e := range items {
		out[e.Key] = e
	}
	return out
}

func TestToolDefaults_Routes_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")
	s1, s2 := h.sensor(tid), h.sensor(tid)
	installToolManifest(t, h, tid, s1)
	installToolManifest(t, h, tid, s2)
	const base = "/api/v1/sensors/tool-defaults"

	// Every member reads; one tool (nuclei) with settings on two sensors.
	var list handler.ToolDefaultsListResponse
	for _, u := range []policyUser{owner, admin, member, viewer} {
		mustJSON(t, h.expect(u, http.MethodGet, base, "", http.StatusOK), &list)
		if len(list.Items) != 1 || list.Items[0].Tool != "nuclei" || list.Items[0].Sensors != 2 || list.Items[0].Stored ||
			!strings.Contains(string(list.Items[0].Schema), "rate_limit") {
			t.Fatalf("%s list = %+v", u.role, list)
		}
	}

	// Only owners and administrators save and reset.
	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":100}}`, http.StatusForbidden)
		h.expect(u, http.MethodDelete, base+"/nuclei", "", http.StatusForbidden)
	}
	// The organization may raise a narrowing option above the tool default.
	var saved handler.ToolDefaultsResponse
	mustJSON(t, h.expect(admin, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":900}}`, http.StatusOK), &saved)
	if !saved.Stored || saved.Values["rate_limit"] != float64(900) || saved.UpdatedBy == nil || *saved.UpdatedBy != admin.id || len(saved.Problems) != 0 {
		t.Fatalf("saved = %+v", saved)
	}

	// Invalid values are refused by path; nothing changes.
	for in, path := range map[string]string{
		`{"values":{"rate_limit":99999}}`: "/rate_limit",
		`{"values":{"headless":true}}`:    "/headless",
		`{"values":{"bogus":1}}`:          "/bogus",
	} {
		if raw := h.expect(admin, http.MethodPut, base+"/nuclei", in, http.StatusUnprocessableEntity); !strings.Contains(raw, `"path":"`+path+`"`) {
			t.Fatalf("%s: %s", in, raw)
		}
	}
	h.expect(admin, http.MethodPut, base+"/nuclei", `{"values":{},"extra":1}`, http.StatusBadRequest)
	// A tool without settings, or on no sensor of the organization.
	h.expect(admin, http.MethodPut, base+"/httpx", `{"values":{}}`, http.StatusNotFound)
	h.expect(admin, http.MethodPut, base+"/naabu", `{"values":{}}`, http.StatusNotFound)

	// Each sensor shows what it inherits; its effective value names the
	// organization as the source.
	var sl handler.SensorToolSettingsListResponse
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s1+"/tool-settings", "", http.StatusOK), &sl)
	if sl.Items[0].OrganizationValues["rate_limit"] != float64(900) || len(sl.Items[0].Values) != 0 {
		t.Fatalf("sensor view = %+v", sl.Items[0])
	}
	var eff handler.SensorEffectiveToolSettingsResponse
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s1+"/tool-settings/nuclei/effective", "", http.StatusOK), &eff)
	if r := effectiveByKey(eff.Items)["rate_limit"]; r.Value != float64(900) || r.Source != "tenant" || len(r.Chain) != 2 {
		t.Fatalf("inherited rate_limit = %+v", r)
	}
	// The sensor overrides it below the organization's value; the chain
	// keeps the organization's.
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+s1+"/tool-settings/nuclei", `{"values":{"rate_limit":300}}`, http.StatusOK)
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s1+"/tool-settings/nuclei/effective", "", http.StatusOK), &eff)
	r := effectiveByKey(eff.Items)["rate_limit"]
	if r.Value != float64(300) || r.Source != "sensor" ||
		fmt.Sprint(r.Chain) != "[{default 150} {tenant 900} {sensor 300}]" {
		t.Fatalf("overridden rate_limit = %+v", r)
	}

	// Another organization: sees none of it, cannot change it.
	var theirs handler.ToolDefaultsListResponse
	mustJSON(t, h.expect(outsider, http.MethodGet, base, "", http.StatusOK), &theirs)
	if len(theirs.Items) != 0 {
		t.Fatalf("outsider sees %+v", theirs)
	}
	h.expect(outsider, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":1}}`, http.StatusNotFound)
	h.expect(outsider, http.MethodDelete, base+"/nuclei", "", http.StatusNoContent) // nothing of theirs to reset
	mustJSON(t, h.expect(admin, http.MethodGet, base, "", http.StatusOK), &list)
	if list.Items[0].Values["rate_limit"] != float64(900) {
		t.Fatalf("another organization changed the defaults: %+v", list.Items[0])
	}

	// A sensor whose tool version refuses the value: the save names it.
	installToolManifestWith(t, h, tid, s2, strings.Replace(toolSettingsConfig, `"maximum":5000`, `"maximum":500`, 1))
	raw := h.expect(owner, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":800}}`, http.StatusUnprocessableEntity)
	if !strings.Contains(raw, `"path":"/rate_limit"`) || !strings.Contains(raw, "authzpol-"+s2[:8]) {
		t.Fatalf("narrower sensor: %s", raw)
	}
	// The stored 900 now fails on that sensor: the list says where.
	mustJSON(t, h.expect(admin, http.MethodGet, base, "", http.StatusOK), &list)
	if len(list.Items[0].Problems) != 1 || list.Items[0].Problems[0].SensorID != s2 {
		t.Fatalf("problems = %+v", list.Items[0].Problems)
	}
	h.expect(owner, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":400}}`, http.StatusOK)

	// Reset, audited; a second reset is a no-op.
	h.expect(admin, http.MethodDelete, base+"/nuclei", "", http.StatusNoContent)
	h.expect(admin, http.MethodDelete, base+"/nuclei", "", http.StatusNoContent)
	mustJSON(t, h.expect(viewer, http.MethodGet, base, "", http.StatusOK), &list)
	if list.Items[0].Stored {
		t.Fatalf("after reset = %+v", list.Items[0])
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
	        AND action = 'settings.updated' AND resource_type = 'tenant' AND changes::text LIKE '%tool_settings.nuclei.rate_limit%'`, tid, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 900, 400, the reset
		t.Fatalf("audit rows = %d, want 3", n)
	}
}

// The claim layers: the organization's defaults go to the tenant's own
// sensors, without the keys a sensor overrides; never to a platform sensor
// or another organization's sensor; values a sensor's schema refuses fail
// its jobs; a scan may only lower the organization's values.
func TestToolDefaults_ClaimLayers_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin := h.member(tid, "admin")
	own, theirs := h.sensor(tid), h.sensor(other)
	installToolManifestWith(t, h, tid, own, layeredToolConfig)
	installToolManifestWith(t, h, other, theirs, layeredToolConfig)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/tool-defaults/nuclei", `{"values":{"retries":3,"workers":50}}`, http.StatusOK)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+own+"/tool-settings/nuclei", `{"values":{"retries":0}}`, http.StatusOK)

	repo := postgres.NewSensorRepository(&postgres.DB{DB: h.db})
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())
	ctx := context.Background()
	tenant := shared.MustIDFromString(tid)

	tl, sl, err := svc.ToolSettingsLayers(ctx, tenant, shared.MustIDFromString(own), "nuclei")
	if err != nil || fmt.Sprint(tl) != "map[workers:50]" || fmt.Sprint(sl) != "map[retries:0]" {
		t.Fatalf("own sensor: tenant=%v sensor=%v err=%v", tl, sl, err)
	}
	// Another organization's sensor, claimed under this tenant: nothing.
	if tl, sl, err := svc.ToolSettingsLayers(ctx, tenant, shared.MustIDFromString(theirs), "nuclei"); err != nil || tl != nil || sl != nil {
		t.Fatalf("another organization's sensor: %v %v %v", tl, sl, err)
	}
	// A shared platform sensor: never the organization's defaults, even
	// with a manifest that declares the tool.
	plat := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
	        VALUES ($1, NULL, $2, 'worker', 'active', 'unknown', 'daemon', $3, 'octs_plt', 'instance')`, plat, "plat-"+plat[:8], "hash-"+plat)
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, plat) })
	installToolManifestWith(t, h, tid, plat, layeredToolConfig)
	if tl, sl, err := svc.ToolSettingsLayers(ctx, tenant, shared.MustIDFromString(plat), "nuclei"); err != nil || tl != nil || sl != nil {
		t.Fatalf("platform sensor: %v %v %v", tl, sl, err)
	}
	// Nor is it counted or validated against on the defaults page.
	var dl handler.ToolDefaultsListResponse
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/sensors/tool-defaults", "", http.StatusOK), &dl)
	if len(dl.Items) != 1 || dl.Items[0].Sensors != 1 {
		t.Fatalf("defaults list counts the platform sensor: %+v", dl.Items)
	}

	// A scan may lower the organization's value, not raise it; a sensor's
	// raise lets a scan go up to it.
	h.exec(`UPDATE sensors SET reported_tool_names = ARRAY['nuclei'] WHERE id = $1`, own)
	h.expect(admin, http.MethodDelete, "/api/v1/sensors/"+own+"/tool-settings/nuclei", "", http.StatusNoContent)
	if err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"retries": float64(2)}); err != nil {
		t.Fatalf("lowering the organization's 3: %v", err)
	}
	if err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"retries": float64(4)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("raising the organization's 3: %v", err)
	}
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+own+"/tool-settings/nuclei", `{"values":{"retries":5}}`, http.StatusOK)
	if err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"retries": float64(4)}); err != nil {
		t.Fatalf("up to the sensor's raise: %v", err)
	}
	h.expect(admin, http.MethodPost, "/api/v1/sensors/"+own+"/tool-settings/nuclei/preview", `{"config":{"retries":6}}`, http.StatusUnprocessableEntity)

	// A sensor upgrade narrows workers below the organization's 50: the
	// tool's jobs on that sensor fail rather than run without it.
	installToolManifestWith(t, h, tid, own, strings.Replace(layeredToolConfig, `"maximum":200`, `"maximum":40`, 1))
	if _, _, err := svc.ToolSettingsLayers(ctx, tenant, shared.MustIDFromString(own), "nuclei"); !errors.Is(err, sensor.ErrToolSettingsInvalid) {
		t.Fatalf("after a narrowing upgrade: %v", err)
	}
	var sv handler.SensorToolSettingsListResponse
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/sensors/"+own+"/tool-settings", "", http.StatusOK), &sv)
	if len(sv.Items[0].OrganizationProblems) != 1 || sv.Items[0].OrganizationProblems[0].Path != "/workers" {
		t.Fatalf("organization problems = %+v", sv.Items[0].OrganizationProblems)
	}
}

type denyStepUp struct{ calls int }

func (d *denyStepUp) RequireRecentAuth(context.Context, string) error {
	d.calls++
	return errStepUp
}

var errStepUp = errors.New("step-up required")

// Setting an Impact (T1) option needs step-up, in both layers; other
// changes and removing an Impact value do not.
func TestToolDefaults_ImpactNeedsStepUp_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid := h.tenant()
	sid := h.sensor(tid)
	installToolManifestWith(t, h, tid, sid, layeredToolConfig)
	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop())
	gate := &denyStepUp{}
	svc.SetStepUpGate(gate)
	ctx := context.Background()
	tenant := shared.MustIDFromString(tid)
	vals := func(m map[string]any) map[string]any { return m }

	if _, err := svc.UpdateToolDefaults(ctx, sensorapp.UpdateToolDefaultsInput{TenantID: tenant, Tool: "nuclei",
		Values: vals(map[string]any{"workers": float64(10)})}); err != nil || gate.calls != 0 {
		t.Fatalf("a non-Impact change: %v (gate %d)", err, gate.calls)
	}
	if _, err := svc.UpdateToolDefaults(ctx, sensorapp.UpdateToolDefaultsInput{TenantID: tenant, Tool: "nuclei",
		Values: vals(map[string]any{"follow_redirects": true})}); !errors.Is(err, errStepUp) {
		t.Fatalf("an Impact change at the organization: %v", err)
	}
	if _, err := svc.UpdateToolSettings(ctx, sensorapp.UpdateToolSettingsInput{TenantID: tid, SensorID: sid, Tool: "nuclei",
		Values: vals(map[string]any{"follow_redirects": true})}); !errors.Is(err, errStepUp) {
		t.Fatalf("an Impact change on the sensor: %v", err)
	}
	// Nothing was stored by the refused changes.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM tenant_tool_settings WHERE tenant_id = $1 AND "values" ? 'follow_redirects'`, tid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stored after refusal: %d %v", n, err)
	}
}
