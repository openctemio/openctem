package routes

// GET /api/v1/tenant-tools/availability end to end
// (docs/architecture/tool-availability.md): the catalog joined with the
// tools the tenant's sensors report, the derived status, the zone filter,
// the sensor list gated on sensors:read, and tenant isolation (another
// tenant's sensors, custom tools and zones never count or show).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	toolapp "github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newToolAvailabilityHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()

	sensorSvc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, log)
	toolSvc := toolapp.NewService(postgres.NewToolRepository(db), postgres.NewTenantToolConfigRepository(db),
		postgres.NewToolExecutionRepository(db), log)
	toolSvc.SetAvailabilitySources(sensorSvc, postgres.NewScanZoneRepository(db), postgres.NewSensorGrantRepository(db))

	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Tool: handler.NewToolHandler(toolSvc, validator.New(), log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantapp.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

// availabilitySensor inserts an active daemon sensor of tenantID that last
// heartbeated lastSeen ago and reports reportedTools (JSON array), with a
// broad trusted grant (the default grant of a new sensor only allows
// passive work).
func (h *authzPolicyHarness) availabilitySensor(tenantID, name string, lastSeen time.Duration, health, reportedTools string, toolNames []string) string {
	h.t.Helper()
	id := uuid.NewString()
	seen := time.Now().Add(-lastSeen)
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix,
	            last_seen_at, heartbeat_interval_seconds, heartbeat_due_at, reported_tools, reported_tool_names, reported_at,
	            trust_level)
	        VALUES ($1, $2, $3, 'worker', 'active', $4, 'daemon', $5, 'octs_tst', $6, 60, $7, $8::jsonb, $9::text[], $6, 'trusted')`,
		id, tenantID, name, health, "hash-"+id, seen, seen.Add(60*time.Second), reportedTools, "{"+join(toolNames)+"}")
	h.exec(`UPDATE sensor_grants SET job_types = NULL, tools = NULL, capabilities = NULL, tier_ceiling = 2,
	            target_network = 'any', target_cidrs = NULL, target_domains = NULL WHERE sensor_id = $1`, id)
	return id
}

func join(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func availabilityByName(t *testing.T, body string) (map[string]handler.ToolAvailabilityItem, handler.ToolAvailabilityResponse) {
	t.Helper()
	var resp handler.ToolAvailabilityResponse
	mustJSON(t, body, &resp)
	out := make(map[string]handler.ToolAvailabilityItem, len(resp.Items))
	for _, it := range resp.Items {
		out[it.Name] = it
	}
	return out, resp
}

func TestToolAvailability_Routes_DB(t *testing.T) {
	h := newToolAvailabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, outsider := h.member(tid, "admin"), h.member(other, "admin")

	online := h.availabilitySensor(tid, "edge-online", 5*time.Second, "online",
		`[{"name":"nuclei","version":"3.4.2","installed":true,"content":[{"name":"templates","version":"v10.2.0","managed":true}]},
		  {"name":"trivy","version":"0.50.0","installed":true}]`, []string{"nuclei", "trivy"})
	h.availabilitySensor(tid, "edge-offline", 2*time.Hour, "offline",
		`[{"name":"semgrep","version":"1.80.0","installed":true},{"name":"nuclei","version":"3.3.0","installed":true}]`,
		[]string{"semgrep", "nuclei"})
	// Another tenant's online sensor with checkov, and its custom tool.
	h.availabilitySensor(other, "theirs", 5*time.Second, "online",
		`[{"name":"checkov","version":"3.2.0","installed":true}]`, []string{"checkov"})
	h.exec(`INSERT INTO tools (tenant_id, name, display_name, install_method, is_builtin) VALUES ($1, 'zz-their-tool', 'Theirs', 'binary', false)`, other)
	// The tenant's own custom tool with a minimum version, and trivy's
	// tenant override: the minimum above what the sensor runs.
	h.exec(`INSERT INTO tools (tenant_id, name, display_name, install_method, is_builtin, min_version) VALUES ($1, 'zz-our-tool', 'Ours', 'binary', false, 'v1.0.0')`, tid)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tools WHERE tenant_id = ANY($1::uuid[])`, "{"+tid+","+other+"}")
	})

	// Zones: the online sensor is in zone A; zone B belongs to the other tenant.
	zoneA, zoneB := uuid.NewString(), uuid.NewString()
	h.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'dmz', '{10.0.0.0/8}')`, zoneA, tid)
	h.exec(`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`, tid, zoneA, online)
	h.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'theirs', '{10.0.0.0/8}')`, zoneB, other)

	const path = "/api/v1/tenant-tools/availability"
	got, resp := availabilityByName(t, h.expect(admin, http.MethodGet, path, "", http.StatusOK))

	nuclei := got["nuclei"]
	if nuclei.Status != "ready" || nuclei.SensorsOnline != 1 || nuclei.SensorsTotal != 2 || !nuclei.Enabled || nuclei.Tool == nil {
		t.Fatalf("nuclei = %+v", nuclei)
	}
	if nuclei.MinReportedVersion != "v3.3.0" || nuclei.MaxReportedVersion != "v3.4.2" || !nuclei.UpdateAvailable {
		t.Fatalf("nuclei versions = %+v", nuclei)
	}
	if len(nuclei.Content) != 1 || nuclei.Content[0].Name != "templates" || nuclei.Content[0].Versions[0] != "v10.2.0" {
		t.Fatalf("nuclei content = %+v", nuclei.Content)
	}
	if len(nuclei.Sensors) != 2 || nuclei.Sensors[0].ID != online || !nuclei.Sensors[0].Online ||
		len(nuclei.Sensors[0].Zones) != 1 || nuclei.Sensors[0].Zones[0].Name != "dmz" || nuclei.Sensors[1].Online {
		t.Fatalf("nuclei sensors = %+v", nuclei.Sensors)
	}
	if st := got["semgrep"].Status; st != "offline_only" {
		t.Errorf("semgrep: %s, want offline_only", st)
	}
	// Isolation: the other tenant's checkov sensor does not count.
	if c := got["checkov"]; c.Status != "no_sensor" || c.SensorsTotal != 0 {
		t.Errorf("checkov = %+v, want no_sensor (another tenant's sensor)", c)
	}
	if _, leaked := got["zz-their-tool"]; leaked {
		t.Error("another tenant's custom tool is listed")
	}
	if o := got["zz-our-tool"]; o.Status != "no_sensor" || o.MinVersion != "v1.0.0" || o.Tool == nil || o.Tool.MinVersion != "v1.0.0" {
		t.Errorf("own custom tool = %+v", o)
	}
	if st := got["gitleaks"].Status; st != "disabled" {
		t.Errorf("gitleaks (inactive in the catalog): %s, want disabled", st)
	}
	if resp.Summary["ready"] < 2 || resp.ComputedAt == "" {
		t.Errorf("summary %+v computed_at %q", resp.Summary, resp.ComputedAt)
	}

	// Zone filter: only the zone's sensors count.
	inZone, zresp := availabilityByName(t, h.expect(admin, http.MethodGet, path+"?zone_id="+zoneA, "", http.StatusOK))
	if inZone["nuclei"].SensorsTotal != 1 || inZone["semgrep"].Status != "no_sensor" || zresp.ZoneID != zoneA {
		t.Errorf("zone view: nuclei %+v semgrep %s zone %q", inZone["nuclei"], inZone["semgrep"].Status, zresp.ZoneID)
	}
	h.expect(admin, http.MethodGet, path+"?zone_id="+zoneB, "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, path+"?zone_id=not-a-uuid", "", http.StatusBadRequest)

	// The other tenant sees its own sensor, none of ours.
	theirs, _ := availabilityByName(t, h.expect(outsider, http.MethodGet, path, "", http.StatusOK))
	if theirs["checkov"].Status != "ready" || theirs["nuclei"].Status != "no_sensor" {
		t.Errorf("other tenant: checkov %s nuclei %s", theirs["checkov"].Status, theirs["nuclei"].Status)
	}
	if _, leaked := theirs["zz-our-tool"]; leaked {
		t.Error("our custom tool is listed to the other tenant")
	}

	// A caller with tenant tools but not sensors: counts, no sensor list.
	toolsOnly := h.member(tid, "member")
	h.customRoleMember(toolsOnly, tid, permission.TenantToolsRead)
	h.mintToken(&toolsOnly, tid)
	limited, _ := availabilityByName(t, h.expect(toolsOnly, http.MethodGet, path, "", http.StatusOK))
	if n := limited["nuclei"]; n.SensorsOnline != 1 || len(n.Sensors) != 0 {
		t.Errorf("without sensors:read: nuclei %+v, want counts and no sensors", n)
	}
	// Without tenant tools: refused.
	nothing := h.member(tid, "member")
	h.customRoleMember(nothing, tid, permission.SensorsRead)
	h.mintToken(&nothing, tid)
	h.expect(nothing, http.MethodGet, path, "", http.StatusForbidden)

	// is_available on the tools-with-config list follows the same source,
	// and the tenant switch turns a ready tool into disabled.
	allTools := h.expect(admin, http.MethodGet, "/api/v1/tenant-tools/all-tools?per_page=100", "", http.StatusOK)
	var list struct {
		Items []handler.ToolWithConfigResponse `json:"items"`
	}
	mustJSON(t, allTools, &list)
	avail := map[string]bool{}
	for _, it := range list.Items {
		avail[it.Tool.Name] = it.IsAvailable
	}
	if !avail["nuclei"] || avail["semgrep"] || avail["checkov"] {
		t.Errorf("is_available: nuclei %v semgrep %v checkov %v, want true false false", avail["nuclei"], avail["semgrep"], avail["checkov"])
	}
	// The tenant switch on a tool it never configured (no row: enabled)
	// creates the row; another tenant's custom tool id is ignored.
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenant_tool_configs WHERE tenant_id = ANY($1::uuid[])`, "{"+tid+","+other+"}")
	})
	var nucleiID, theirToolID string
	if err := h.db.QueryRowContext(context.Background(), `SELECT id FROM tools WHERE name = 'nuclei' AND tenant_id IS NULL`).Scan(&nucleiID); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRowContext(context.Background(), `SELECT id FROM tools WHERE name = 'zz-their-tool'`).Scan(&theirToolID); err != nil {
		t.Fatal(err)
	}
	h.expect(admin, http.MethodPost, "/api/v1/tenant-tools/bulk/disable", `{"tool_ids":["`+nucleiID+`","`+theirToolID+`"]}`, http.StatusNoContent)
	var rows int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM tenant_tool_configs WHERE tool_id = $1`, theirToolID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("another tenant's custom tool got %d config rows (%v)", rows, err)
	}
	off, _ := availabilityByName(t, h.expect(admin, http.MethodGet, path, "", http.StatusOK))
	if off["nuclei"].Status != "disabled" || off["nuclei"].Enabled {
		t.Errorf("nuclei after the tenant switched it off: %+v", off["nuclei"])
	}
	theirs, _ = availabilityByName(t, h.expect(outsider, http.MethodGet, path, "", http.StatusOK))
	if !theirs["nuclei"].Enabled {
		t.Error("our switch turned nuclei off for the other tenant")
	}
	h.expect(admin, http.MethodPost, "/api/v1/tenant-tools/bulk/enable", `{"tool_ids":["`+nucleiID+`"]}`, http.StatusNoContent)
	on, _ := availabilityByName(t, h.expect(admin, http.MethodGet, path, "", http.StatusOK))
	if on["nuclei"].Status != "ready" {
		t.Errorf("nuclei after the tenant switched it back on: %s", on["nuclei"].Status)
	}
}
