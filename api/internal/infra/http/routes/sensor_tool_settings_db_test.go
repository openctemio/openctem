package routes

// Per-sensor tool settings end to end (docs/architecture/sensors.md, "Tool
// settings"): the schema comes from the tool descriptor in the sensor's
// current manifest; members and viewers read, only owners and
// administrators save and reset; another organization's sensor and a
// platform sensor answer 404; every change is audited.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"errors"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const toolSettingsConfig = `{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{` +
	`"rate_limit":{"type":"integer","maximum":5000,"default":150,"x-octm-common":"rate","x-octm-flag":"-rate-limit","x-octm-scope":"scan"},` +
	`"headless":{"type":"boolean","default":false,"x-octm-tier":"T2","x-octm-flag":"-headless"}}}`

// installToolManifest stores a current manifest for the sensor whose
// nuclei descriptor declares a settings schema and whose httpx has none.
func installToolManifest(t *testing.T, h *authzPolicyHarness, tenantID, sensorID string) {
	t.Helper()
	installToolManifestWith(t, h, tenantID, sensorID, toolSettingsConfig)
}

func installToolManifestWith(t *testing.T, h *authzPolicyHarness, tenantID, sensorID, nucleiConfig string) {
	t.Helper()
	contract := func(name, config string) *sensor.ToolContract {
		desc := `{"apiVersion":"openctem.io/tool/v1","name":"` + name + `","version":"1.0.0"`
		if config != "" {
			desc += `,"config":` + config
		}
		desc += `}`
		return &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Version: "1.0.0", Class: "target-scan",
			Tier: "T0", Produces: []string{"finding:vulnerability"}, Descriptor: json.RawMessage(desc)}
	}
	m := sensor.Manifest{Schema: 1, Tools: []sensor.ManifestTool{
		{Name: "nuclei", Installed: true, Contract: contract("nuclei", nucleiConfig)},
		{Name: "httpx", Installed: true, Contract: contract("httpx", "")},
	}}
	digest, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tid, sid := shared.MustIDFromString(tenantID), shared.MustIDFromString(sensorID)
	repo := postgres.NewSensorRepository(&postgres.DB{DB: h.db})
	if _, err := repo.SaveManifest(context.Background(), sensor.ManifestVersion{SensorID: sid, TenantID: &tid,
		Digest: digest, Source: sensor.ManifestSourceSensor, Manifest: m}, nil, time.Now()); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
}

func TestSensorToolSettings_Routes_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")
	sid := h.sensor(tid)
	installToolManifest(t, h, tid, sid)
	base := "/api/v1/sensors/" + sid + "/tool-settings"

	// Every member reads the tools that declare settings.
	var list handler.SensorToolSettingsListResponse
	for _, u := range []policyUser{owner, admin, member, viewer} {
		mustJSON(t, h.expect(u, http.MethodGet, base, "", http.StatusOK), &list)
		if len(list.Items) != 1 || list.Items[0].Tool != "nuclei" || list.Items[0].Stored ||
			!strings.HasPrefix(list.Items[0].SchemaDigest, "sha256:") || !strings.Contains(string(list.Items[0].Schema), "rate_limit") {
			t.Fatalf("%s list = %+v", u.role, list)
		}
	}

	// Only owners and administrators save.
	body := `{"values":{"rate_limit":300}}`
	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodPut, base+"/nuclei", body, http.StatusForbidden)
		h.expect(u, http.MethodDelete, base+"/nuclei", "", http.StatusForbidden)
	}
	h.expect(owner, http.MethodPut, base+"/nuclei", `{"values":{"rate_limit":200}}`, http.StatusOK)
	var saved handler.SensorToolSettingsResponse
	mustJSON(t, h.expect(admin, http.MethodPut, base+"/nuclei", body, http.StatusOK), &saved)
	if !saved.Stored || saved.Values["rate_limit"] != float64(300) || saved.UpdatedBy == nil || *saved.UpdatedBy != admin.id {
		t.Fatalf("saved = %+v", saved)
	}

	// Invalid values are refused by path; nothing is stored.
	for in, path := range map[string]string{
		`{"values":{"rate_limit":99999}}`: "/rate_limit",
		`{"values":{"headless":true}}`:    "/headless",
		`{"values":{"bogus":1}}`:          "/bogus",
	} {
		raw := h.expect(admin, http.MethodPut, base+"/nuclei", in, http.StatusUnprocessableEntity)
		if !strings.Contains(raw, `"path":"`+path+`"`) {
			t.Fatalf("%s: %s", in, raw)
		}
	}
	h.expect(admin, http.MethodPut, base+"/nuclei", `{"values":{},"extra":1}`, http.StatusBadRequest)
	// A tool without a settings schema, or not on the sensor, has none.
	h.expect(admin, http.MethodPut, base+"/httpx", body, http.StatusNotFound)
	h.expect(admin, http.MethodPut, base+"/naabu", body, http.StatusNotFound)
	h.expect(viewer, http.MethodGet, base+"/httpx/effective", "", http.StatusNotFound)

	// The effective view.
	var eff handler.SensorEffectiveToolSettingsResponse
	mustJSON(t, h.expect(viewer, http.MethodGet, base+"/nuclei/effective", "", http.StatusOK), &eff)
	got := map[string]handler.EffectiveToolSettingResponse{}
	for _, e := range eff.Items {
		got[e.Key] = e
	}
	if r := got["rate_limit"]; r.Value != float64(300) || r.Source != "sensor" || r.Flag != "-rate-limit" || r.Common != "rate" || r.Scope != "scan" {
		t.Fatalf("rate_limit = %+v", r)
	}
	if hl := got["headless"]; hl.Value != false || hl.Source != "default" || hl.Tier != "T2" {
		t.Fatalf("headless = %+v", hl)
	}

	// Another organization and a platform sensor: 404 everywhere, nothing
	// changed.
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodGet, base + "/nuclei/effective", ""},
		{http.MethodPut, base + "/nuclei", `{"values":{"rate_limit":1}}`},
		{http.MethodDelete, base + "/nuclei", ""},
	} {
		h.expect(outsider, req.method, req.path, req.body, http.StatusNotFound)
	}
	plat := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
	        VALUES ($1, NULL, $2, 'worker', 'active', 'unknown', 'daemon', $3, 'octs_plt', 'instance')`, plat, "plat-"+plat[:8], "hash-"+plat)
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, plat) })
	h.expect(admin, http.MethodGet, "/api/v1/sensors/"+plat+"/tool-settings", "", http.StatusNotFound)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+plat+"/tool-settings/nuclei", body, http.StatusNotFound)
	mustJSON(t, h.expect(admin, http.MethodGet, base, "", http.StatusOK), &list)
	if list.Items[0].Values["rate_limit"] != float64(300) {
		t.Fatalf("values changed by a refused request: %+v", list.Items[0].Values)
	}

	// Reset, audited; a second reset is a no-op.
	h.expect(admin, http.MethodDelete, base+"/nuclei", "", http.StatusNoContent)
	h.expect(admin, http.MethodDelete, base+"/nuclei", "", http.StatusNoContent)
	var after handler.SensorToolSettingsListResponse
	mustJSON(t, h.expect(viewer, http.MethodGet, base, "", http.StatusOK), &after)
	if after.Items[0].Stored || len(after.Items[0].Values) != 0 {
		t.Fatalf("after reset = %+v", after.Items[0])
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
	        AND action = 'sensor.updated' AND changes::text LIKE '%tool_settings.nuclei.rate_limit%'`, tid, sid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 { // owner's save, admin's change, the reset
		t.Fatalf("audit rows = %d, want 3", n)
	}
}

// The claim-time layer: the stored values when the schema is unchanged or
// changed compatibly; ErrToolSettingsInvalid when a sensor upgrade narrowed
// a key below a stored value (the job fails rather than run without them);
// nothing for another tenant or a sensor without settings.
func TestSensorToolSettings_ClaimLayer_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin := h.member(tid, "admin")
	sid := h.sensor(tid)
	installToolManifest(t, h, tid, sid)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+sid+"/tool-settings/nuclei", `{"values":{"rate_limit":300}}`, http.StatusOK)

	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop())
	ctx := context.Background()
	tenant, sensorID := shared.MustIDFromString(tid), shared.MustIDFromString(sid)

	layer, err := sensorLayerOf(ctx, svc, tenant, sensorID, "nuclei")
	if err != nil || fmt.Sprint(layer["rate_limit"]) != "300" {
		t.Fatalf("layer = %v, %v", layer, err)
	}
	if l, err := sensorLayerOf(ctx, svc, shared.MustIDFromString(other), sensorID, "nuclei"); err != nil || l != nil {
		t.Fatalf("another tenant got %v, %v", l, err)
	}
	if l, err := sensorLayerOf(ctx, svc, tenant, sensorID, "httpx"); err != nil || l != nil {
		t.Fatalf("httpx = %v, %v", l, err)
	}

	// A compatible upgrade (another digest, the value still valid).
	installToolManifestWith(t, h, tid, sid, strings.Replace(toolSettingsConfig, `"maximum":5000`, `"maximum":4000`, 1))
	if layer, err := sensorLayerOf(ctx, svc, tenant, sensorID, "nuclei"); err != nil || fmt.Sprint(layer["rate_limit"]) != "300" {
		t.Fatalf("after a compatible upgrade = %v, %v", layer, err)
	}
	// An upgrade that narrows rate_limit below the stored value.
	installToolManifestWith(t, h, tid, sid, strings.Replace(toolSettingsConfig, `"maximum":5000`, `"maximum":200`, 1))
	if _, err := sensorLayerOf(ctx, svc, tenant, sensorID, "nuclei"); !errors.Is(err, sensor.ErrToolSettingsInvalid) {
		t.Fatalf("after a narrowing upgrade: %v", err)
	}
	// The list shows why.
	var list handler.SensorToolSettingsListResponse
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/sensors/"+sid+"/tool-settings", "", http.StatusOK), &list)
	if len(list.Items[0].Problems) != 1 || list.Items[0].Problems[0].Path != "/rate_limit" {
		t.Fatalf("problems = %+v", list.Items[0].Problems)
	}
	// An upgrade that drops the settings.
	installToolManifestWith(t, h, tid, sid, "")
	if _, err := sensorLayerOf(ctx, svc, tenant, sensorID, "nuclei"); !errors.Is(err, sensor.ErrToolSettingsInvalid) {
		t.Fatalf("after the settings were dropped: %v", err)
	}
	// Reset still works for a tool that no longer declares settings.
	h.expect(admin, http.MethodDelete, "/api/v1/sensors/"+sid+"/tool-settings/nuclei", "", http.StatusNoContent)
	if l, err := sensorLayerOf(ctx, svc, tenant, sensorID, "nuclei"); err != nil || l != nil {
		t.Fatalf("after reset = %v, %v", l, err)
	}
}

// previewToolConfig: a scan-scope common option (retries) and a
// sensor-only key (workers).
const previewToolConfig = `{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{` +
	`"retries":{"type":"integer","minimum":0,"maximum":5,"default":1,"x-octm-common":"retries","x-octm-flag":"-retries","x-octm-scope":"scan"},` +
	`"workers":{"type":"integer","minimum":1,"maximum":200,"default":25,"x-octm-flag":"-w","x-octm-scope":"sensor"}}}`

// The preview resolves a scan's config over the sensor's settings as the
// sensor will; every member reads it, a config the sensor would refuse is
// 422 by path, and another organization's sensor answers 404.
func TestSensorToolSettings_Preview_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, viewer := h.member(tid, "admin"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")
	sid := h.sensor(tid)
	installToolManifestWith(t, h, tid, sid, previewToolConfig)
	base := "/api/v1/sensors/" + sid + "/tool-settings/nuclei"
	h.expect(admin, http.MethodPut, base, `{"values":{"retries":3}}`, http.StatusOK)

	var p handler.SensorToolSettingsPreviewResponse
	mustJSON(t, h.expect(viewer, http.MethodPost, base+"/preview", `{"config":{"retries":2,"rate_limit":10,"template_id":"x"}}`, http.StatusOK), &p)
	got := map[string]handler.EffectiveToolSettingResponse{}
	for _, e := range p.Items {
		got[e.Key] = e
	}
	if r := got["retries"]; r.Value != float64(2) || r.Source != "scan" {
		t.Fatalf("retries = %+v", r)
	}
	if b := got["workers"]; b.Value != float64(25) || b.Source != "default" {
		t.Fatalf("workers = %+v", b)
	}
	if len(p.Ignored) != 1 || p.Ignored[0] != "template_id" {
		t.Fatalf("ignored = %v", p.Ignored)
	}

	for in, path := range map[string]string{
		`{"config":{"retries":4}}`:  "/retries", // above the sensor's raise
		`{"config":{"workers":10}}`: "/workers", // sensor-only
	} {
		if raw := h.expect(viewer, http.MethodPost, base+"/preview", in, http.StatusUnprocessableEntity); !strings.Contains(raw, `"path":"`+path+`"`) {
			t.Fatalf("%s: %s", in, raw)
		}
	}
	h.expect(viewer, http.MethodPost, base+"/preview", `{"config":{},"extra":1}`, http.StatusBadRequest)
	h.expect(outsider, http.MethodPost, base+"/preview", `{"config":{}}`, http.StatusNotFound)
}

// Saving a scan's tool options is checked against the tenant's sensors for
// that tool: refused only when no sensor would accept them.
func TestSensorToolSettings_CheckScanToolConfig_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")
	strict, lax := h.sensor(tid), h.sensor(tid)
	installToolManifestWith(t, h, tid, strict, previewToolConfig)
	installToolManifestWith(t, h, tid, lax, previewToolConfig)
	h.expect(admin, http.MethodPut, "/api/v1/sensors/"+lax+"/tool-settings/nuclei", `{"values":{"retries":4}}`, http.StatusOK)
	h.exec(`UPDATE sensors SET reported_tool_names = ARRAY['nuclei'] WHERE id = ANY($1::uuid[])`, "{"+strict+","+lax+"}")

	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop())
	tenant := shared.MustIDFromString(tid)
	ctx := context.Background()
	if err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"retries": float64(4)}); err != nil {
		t.Fatalf("accepted by the lax sensor, refused: %v", err)
	}
	err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"retries": float64(5)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no sensor accepts retries 5: err = %v", err)
	}
	if err := svc.CheckScanToolConfig(ctx, tenant, "nuclei", map[string]any{"workers": float64(10)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a sensor-only option: err = %v", err)
	}
	if err := svc.CheckScanToolConfig(ctx, tenant, "naabu", map[string]any{"retries": float64(9)}); err != nil {
		t.Fatalf("no sensor declares naabu settings: %v", err)
	}
	if err := svc.CheckScanToolConfig(ctx, shared.MustIDFromString(h.tenant()), "nuclei", map[string]any{"retries": float64(5)}); err != nil {
		t.Fatalf("another tenant has no such sensor: %v", err)
	}
}

// sensorLayerOf is the sensor layer of ToolSettingsLayers.
func sensorLayerOf(ctx context.Context, svc *sensorapp.SensorService, tenantID, sensorID shared.ID, tool string) (map[string]any, error) {
	_, layer, err := svc.ToolSettingsLayers(ctx, tenantID, sensorID, tool)
	return layer, err
}
