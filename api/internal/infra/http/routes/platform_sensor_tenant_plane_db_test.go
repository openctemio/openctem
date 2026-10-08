package routes

// Shared platform sensors on the tenant plane (research/67). A platform
// sensor's row carries some tenant_id (the operator's), but it is never that
// tenant's sensor: every tenant route on one sensor answers 404 for it, the
// lists and counts leave it out, and a tenant sees platform scanning only as
// an aggregated service (GET /api/v1/platform/scanning) with no sensor id,
// name, host, address or version and no other tenant's load. A platform
// job's command and logs never name the sensor and mask its own addresses
// and paths.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// platformPlaneHarness is the authorization harness with the sensor,
// command (and logs) and platform scanning routes, and a switch for whether
// tenants may use platform scanning.
type platformPlaneHarness struct {
	*authzPolicyHarness
	routes  [][2]string // method, path of every /api/v1/sensors/{id}... route
	allowed bool
}

func newPlatformPlaneHarness(t *testing.T) *platformPlaneHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	h := &platformPlaneHarness{authzPolicyHarness: base}

	sensorRepo := postgres.NewSensorRepository(db)
	sh := handler.NewSensorHandler(sensorapp.NewSensorService(sensorRepo, nil, log), validator.New(), log)
	sh.SetGrantService(sensorgrant.NewService(postgres.NewSensorGrantRepository(db), sensorRepo, log))
	ch := handler.NewCommandHandler(commandapp.NewService(postgres.NewCommandRepository(db), log,
		commandapp.WithSensorLookup(sensorRepo)), validator.New(), log)
	ch.SetCommandLogs(commandlog.NewService(postgres.NewCommandLogRepository(db)))
	ps := handler.NewPlatformScanningHandler(sensorapp.NewPlatformScanningService(sensorRepo,
		func(context.Context, shared.ID) (bool, string) { return h.allowed, "not in this test" }), log)

	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{Sensor: sh, Command: ch, PlatformScanning: ps, StepUp: alwaysSteppedUp{}},
		cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantapp.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	if err := router.Walk(func(method, path string, _ http.Handler) error {
		if strings.HasPrefix(path, "/api/v1/sensors/{id}") {
			h.routes = append(h.routes, [2]string{method, path})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return h
}

// platformSensor inserts an online platform sensor whose row carries
// tenantID, with identifying details a tenant must never see.
func (h *platformPlaneHarness) platformSensor(tenantID, name, region, health string, tools []string) string {
	h.t.Helper()
	id := uuid.NewString()
	seen := time.Now().Add(-5 * time.Second)
	reported, _ := json.Marshal(func() []map[string]any {
		out := []map[string]any{}
		for _, t := range tools {
			out = append(out, map[string]any{"name": t, "version": "1.0.0", "installed": true})
		}
		return out
	}())
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix,
	            is_platform_sensor, hostname, ip_address, version, region, capabilities,
	            last_seen_at, heartbeat_interval_seconds, heartbeat_due_at, reported_tools, reported_tool_names, reported_at)
	        VALUES ($1, $2, $3, 'worker', 'active', $4, 'daemon', $5, 'octs_plt', TRUE, $6, '10.9.8.7', 'v9.9.9-secret', $7,
	            '{dast}', $8, 60, $9, $10::jsonb, $11::text[], $8)`,
		id, tenantID, name, health, "hash-"+id, name+".plat.internal", region, seen, seen.Add(60*time.Second),
		string(reported), "{"+strings.Join(tools, ",")+"}")
	return id
}

func (h *platformPlaneHarness) platformJob(tenantID, sensorID, status, errMsg string) string {
	h.t.Helper()
	id := uuid.NewString()
	var sid any
	if sensorID != "" {
		sid = sensorID
	}
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status, is_platform_job, sensor_id, platform_sensor_id, error_message, result)
	        VALUES ($1, $2, 'scan', '{}'::jsonb, $3, TRUE, $4, $4, $5,
	                '{"metadata":{"workdir":"/opt/sensor/work/x","peer":"10.9.8.7:443","target":"93.184.216.34"}}'::jsonb)`,
		id, tenantID, status, sid, errMsg)
	return id
}

func TestPlatformSensors_TenantRoutesNotFound_DB(t *testing.T) {
	h := newPlatformPlaneHarness(t)
	operator, other := h.tenant(), h.tenant()
	admin, otherAdmin := h.member(operator, "admin"), h.member(other, "admin")
	plat := h.platformSensor(operator, "plat-node-7", "eu", "online", []string{"nuclei"})
	own := h.sensor(operator)

	if len(h.routes) < 15 {
		t.Fatalf("only %d sensor routes walked: %v", len(h.routes), h.routes)
	}
	// Every route on one sensor, read or write, answers 404 for a platform
	// sensor: to the tenant its row carries and to any other tenant alike.
	for _, rt := range h.routes {
		path := strings.ReplaceAll(strings.ReplaceAll(rt[1], "{id}", plat), "{key_id}", uuid.NewString())
		for _, u := range []policyUser{admin, otherAdmin} {
			code, body := h.do(u, rt[0], path, "{}")
			if code != http.StatusNotFound {
				t.Errorf("%s %s as %s: %d, want 404 (%s)", rt[0], rt[1], u.role, code, body)
			}
		}
	}
	// The row is untouched: nothing renamed, revoked or deleted it.
	var name, status string
	if err := h.db.QueryRowContext(context.Background(), `SELECT name, status FROM sensors WHERE id = $1`, plat).Scan(&name, &status); err != nil {
		t.Fatalf("platform sensor gone: %v", err)
	}
	if name != "plat-node-7" || status != "active" {
		t.Fatalf("platform sensor changed by a tenant route: %s %s", name, status)
	}

	// The tenant's own sensor is still reachable through the same guard.
	h.expect(admin, http.MethodGet, "/api/v1/sensors/"+own, "", http.StatusOK)
	h.expect(otherAdmin, http.MethodGet, "/api/v1/sensors/"+own, "", http.StatusNotFound)

	// Lists and counts leave it out; a command cannot be pinned to it.
	for _, path := range []string{"/api/v1/sensors?per_page=100", "/api/v1/sensors/stats",
		"/api/v1/sensors/available-capabilities", "/api/v1/sensors/grant-summaries"} {
		if body := h.expect(admin, http.MethodGet, path, "", http.StatusOK); strings.Contains(body, plat) ||
			strings.Contains(body, "plat-node-7") || strings.Contains(body, "dast") {
			t.Errorf("%s shows the platform sensor: %s", path, body)
		}
	}
	code, body := h.do(admin, http.MethodPost, "/api/v1/commands", `{"type":"health_check","sensor_id":"`+plat+`"}`)
	if code == http.StatusCreated || !strings.Contains(body, "SENSOR_NOT_FOUND") {
		t.Fatalf("command pinned to a platform sensor: %d %s", code, body)
	}
}

func TestPlatformScanning_AggregatedView_DB(t *testing.T) {
	h := newPlatformPlaneHarness(t)
	operator, tid, other := h.tenant(), h.tenant(), h.tenant()
	viewer := h.member(tid, "viewer")
	eu := h.platformSensor(operator, "plat-eu-1", "eu", "online", []string{"nuclei", "httpx"})
	h.platformSensor(operator, "plat-us-1", "us", "offline", []string{"subfinder"})
	// The organization's own platform jobs and another organization's.
	h.platformJob(tid, "", "pending", "")
	h.platformJob(tid, eu, "running", "")
	h.platformJob(other, eu, "running", "")
	h.platformJob(other, "", "pending", "")
	h.platformJob(other, "", "pending", "")

	// Not offered: says nothing else, not even that platform sensors exist.
	h.allowed = false
	body := h.expect(viewer, http.MethodGet, "/api/v1/platform/scanning", "", http.StatusOK)
	var off sensorapp.PlatformScanning
	mustJSON(t, body, &off)
	if off.Offered || off.Status != "" || len(off.Regions) != 0 || len(off.Tools) != 0 || off.YourJobs.Queued != 0 {
		t.Fatalf("not offered, yet: %s", body)
	}

	h.allowed = true
	body = h.expect(viewer, http.MethodGet, "/api/v1/platform/scanning", "", http.StatusOK)
	var got sensorapp.PlatformScanning
	mustJSON(t, body, &got)
	if !got.Offered || got.Status != "available" || got.QueueLimitMinutes != 60 {
		t.Fatalf("offered view: %s", body)
	}
	regions := map[string]string{}
	for _, r := range got.Regions {
		regions[r.Name] = r.Status
	}
	if regions["eu"] != "available" || regions["us"] != "unavailable" || len(regions) != 2 {
		t.Fatalf("regions: %s", body)
	}
	// Only the tools online platform sensors run.
	if strings.Join(got.Tools, ",") != "httpx,nuclei" {
		t.Fatalf("tools %v", got.Tools)
	}
	// The organization's own jobs only.
	if got.YourJobs.Queued != 1 || got.YourJobs.Running != 1 {
		t.Fatalf("your jobs: %+v", got.YourJobs)
	}
	// Nothing that identifies a platform sensor, nor any count or load.
	for _, leak := range []string{eu, "plat-eu-1", "plat.internal", "10.9.8.7", "v9.9.9", "sensors", "capacity", "load", "slots"} {
		if strings.Contains(body, leak) {
			t.Errorf("platform scanning shows %q: %s", leak, body)
		}
	}
	// A busy region: online, every slot taken.
	h.exec(`UPDATE sensors SET max_concurrent_jobs = 1 WHERE id = $1`, eu)
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/platform/scanning", "", http.StatusOK), &got)
	if got.Status != "busy" {
		t.Fatalf("a full region: status %q", got.Status)
	}
}

func TestPlatformJobs_CommandsAndLogsRedacted_DB(t *testing.T) {
	h := newPlatformPlaneHarness(t)
	operator, tid := h.tenant(), h.tenant()
	admin := h.member(tid, "admin")
	plat := h.platformSensor(operator, "plat-node-9", "eu", "online", []string{"nuclei"})
	job := h.platformJob(tid, plat, "failed", "dial 10.9.8.7:5432 from /opt/sensor/bin: refused")
	lines, _ := json.Marshal([]map[string]any{{"ts": "2026-10-07T10:00:00Z", "level": "info",
		"msg": "worker plat-node-9 at 192.168.4.2 wrote /var/lib/sensor/out.json for 93.184.216.34", "source": "/opt/sensor/nuclei",
		"fields": map[string]any{"peer": "10.9.8.7", "target": "example.com"}}})
	h.exec(`INSERT INTO command_logs (tenant_id, command_id, seq, lines, line_count, bytes, dropped)
	        VALUES ($1, $2, 0, $3::jsonb, 1, $4, 0)`, tid, job, string(lines), len(lines))

	for _, path := range []string{"/api/v1/commands/" + job, "/api/v1/commands?per_page=50"} {
		body := h.expect(admin, http.MethodGet, path, "", http.StatusOK)
		for _, leak := range []string{plat, "10.9.8.7", "/opt/sensor"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s shows %q: %s", path, leak, body)
			}
		}
		if !strings.Contains(body, `"platform":true`) || !strings.Contains(body, "93.184.216.34") {
			t.Errorf("%s: no platform flag, or the public target was masked: %s", path, body)
		}
	}

	body := h.expect(admin, http.MethodGet, "/api/v1/commands/"+job+"/logs", "", http.StatusOK)
	for _, leak := range []string{"192.168.4.2", "10.9.8.7", "/var/lib/sensor", "/opt/sensor"} {
		if strings.Contains(body, leak) {
			t.Errorf("logs show %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "93.184.216.34") || !strings.Contains(body, "example.com") {
		t.Errorf("logs lost the tenant's targets: %s", body)
	}

	// A tenant job's logs are shown as written.
	own := h.logsCommand(tid, "scan", `{}`, "connect 10.1.1.1 from /opt/x")
	if body := h.expect(admin, http.MethodGet, "/api/v1/commands/"+own+"/logs", "", http.StatusOK); !strings.Contains(body, "10.1.1.1") {
		t.Errorf("a tenant job's logs were masked: %s", body)
	}
}
