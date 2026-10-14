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
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, is_platform_sensor)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, 'octs_plt', TRUE)`, plat, tid, "plat-"+plat[:8], "hash-"+plat)
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

	layer, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "nuclei")
	if err != nil || fmt.Sprint(layer["rate_limit"]) != "300" {
		t.Fatalf("layer = %v, %v", layer, err)
	}
	if l, err := svc.SensorToolSettingsLayer(ctx, shared.MustIDFromString(other), sensorID, "nuclei"); err != nil || l != nil {
		t.Fatalf("another tenant got %v, %v", l, err)
	}
	if l, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "httpx"); err != nil || l != nil {
		t.Fatalf("httpx = %v, %v", l, err)
	}

	// A compatible upgrade (another digest, the value still valid).
	installToolManifestWith(t, h, tid, sid, strings.Replace(toolSettingsConfig, `"maximum":5000`, `"maximum":4000`, 1))
	if layer, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "nuclei"); err != nil || fmt.Sprint(layer["rate_limit"]) != "300" {
		t.Fatalf("after a compatible upgrade = %v, %v", layer, err)
	}
	// An upgrade that narrows rate_limit below the stored value.
	installToolManifestWith(t, h, tid, sid, strings.Replace(toolSettingsConfig, `"maximum":5000`, `"maximum":200`, 1))
	if _, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "nuclei"); !errors.Is(err, sensor.ErrToolSettingsInvalid) {
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
	if _, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "nuclei"); !errors.Is(err, sensor.ErrToolSettingsInvalid) {
		t.Fatalf("after the settings were dropped: %v", err)
	}
	// Reset still works for a tool that no longer declares settings.
	h.expect(admin, http.MethodDelete, "/api/v1/sensors/"+sid+"/tool-settings/nuclei", "", http.StatusNoContent)
	if l, err := svc.SensorToolSettingsLayer(ctx, tenant, sensorID, "nuclei"); err != nil || l != nil {
		t.Fatalf("after reset = %v, %v", l, err)
	}
}
