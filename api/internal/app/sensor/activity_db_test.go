package sensor_test

// The sensor activity timeline end to end against a migrated database: real
// heartbeats through UpdateHeartbeat, diffed against the stored row, written
// to sensor_events and read back through ListActivity.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	sensorapp "github.com/openctemio/api/internal/app/sensor"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/testdb"
	sensordom "github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type activityHarness struct {
	t   *testing.T
	db  *sql.DB
	svc *sensorapp.SensorService
}

func newActivityHarness(t *testing.T) *activityHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping sensor activity DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, logger.NewNop())
	events := postgres.NewSensorEventRepository(db)
	svc.SetEventRepository(events, sensordom.DefaultEventLimits())
	svc.SetActivityReader(events)
	return &activityHarness{t: t, db: sqldb, svc: svc}
}

func (h *activityHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *activityHarness) tenant() shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'sensor activity IT', $2)`, id.String(), "sact-"+id.String())
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM commands WHERE tenant_id = $1`, id.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensors WHERE tenant_id = $1`, id.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func (h *activityHarness) sensor(tenantID shared.ID) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, 'rda_test', 5)`,
		id.String(), tenantID.String(), "activity-"+id.String()[:8], "hash-"+id.String())
	return id
}

func (h *activityHarness) heartbeat(id shared.ID, d sensorapp.SensorHeartbeatData) {
	h.t.Helper()
	if err := h.svc.UpdateHeartbeat(context.Background(), id, d); err != nil {
		h.t.Fatalf("heartbeat: %v", err)
	}
}

func (h *activityHarness) events(tenantID, id shared.ID) map[string]sensordom.ActivityItem {
	h.t.Helper()
	page, err := h.svc.ListActivity(context.Background(), sensorapp.ActivityInput{
		TenantID: tenantID.String(), SensorID: id.String(), Limit: sensorapp.MaxActivityLimit,
	})
	if err != nil {
		h.t.Fatalf("ListActivity: %v", err)
	}
	// Newest first: keep the latest item of each type.
	out := map[string]sensordom.ActivityItem{}
	for _, it := range page.Items {
		if _, seen := out[it.Type]; !seen {
			out[it.Type] = it
		}
	}
	return out
}

func tool(name, version string, content ...sensordom.ReportedContent) sensordom.ReportedTool {
	return sensordom.ReportedTool{Name: name, Version: version, Installed: true, Content: content}
}

func TestSensorActivity_HeartbeatDiffs_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	id := h.sensor(tid)

	// First heartbeat: a v1 sensor, nothing to compare with yet.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{
		Version: "0.4.1", Protocol: 1, UptimeSeconds: 3600,
		UserAgent: "openctemio-sensor/0.4.1 openctem-sdk-go/0.8.0",
		Report: &sensordom.CapabilityReportInput{Tools: []sensordom.ReportedTool{
			tool("nuclei", "3.1.0"),
			tool("trivy", "0.60.0", sensordom.ReportedContent{Name: "trivy-db", Version: "2026-10-01T00:00:00Z", Managed: true}),
		}},
	})
	ev := h.events(tid, id)
	if len(ev) != 1 || ev["online"].Summary != "Connected for the first time" {
		t.Fatalf("after the first heartbeat: %+v", ev)
	}

	a, err := h.svc.GetSensor(context.Background(), tid.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != "0.4.1" || a.Build.SDKName != "openctem-sdk-go" || a.Build.SDKVersion != "v0.8.0" ||
		a.Build.Product != "openctemio-sensor" {
		t.Fatalf("build from the User-Agent: version=%q build=%+v", a.Version, a.Build)
	}

	// The health checker marks it offline ten minutes later.
	h.exec(`UPDATE sensors SET health = 'offline', last_seen_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, id.String())
	a, _ = h.svc.GetSensor(context.Background(), tid.String(), id.String())
	h.svc.RecordOffline(context.Background(), a)

	// It comes back upgraded, restarted, on protocol v2, with other tools,
	// less capacity and new content.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{
		Version: "0.5.0", Protocol: 2, UptimeSeconds: 30,
		UserAgent: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0",
		Report: &sensordom.CapabilityReportInput{MaxConcurrentJobs: 3, Tools: []sensordom.ReportedTool{
			tool("nuclei", "3.2.0"),
			tool("trivy", "0.60.0", sensordom.ReportedContent{Name: "trivy-db", Version: "2026-10-02T00:00:00Z", Managed: true}),
			tool("semgrep", "1.90.0"),
		}},
	})
	ev = h.events(tid, id)
	want := map[string]string{
		"online":              "status",
		"offline":             "status",
		"restarted":           "status",
		"version_changed":     "updates",
		"sdk_version_changed": "updates",
		"protocol_changed":    "updates",
		"tools_changed":       "updates",
		"capacity_changed":    "updates",
		"content_updated":     "updates",
	}
	for typ, cat := range want {
		it, ok := ev[typ]
		if !ok {
			t.Errorf("missing %s; got %+v", typ, ev)
			continue
		}
		if string(it.Category) != cat || it.Source != sensordom.ActivitySourceSensor {
			t.Errorf("%s: category %s source %s", typ, it.Category, it.Source)
		}
	}
	if d := ev["version_changed"].Details; d["from"] != "v0.4.1" || d["to"] != "v0.5.0" || d["direction"] != "upgrade" {
		t.Errorf("version_changed %+v", d)
	}
	if d := ev["sdk_version_changed"].Details; d["from"] != "v0.8.0" || d["to"] != "v0.9.0" || d["name"] != "openctem-sdk-go" {
		t.Errorf("sdk_version_changed %+v", d)
	}
	if d := ev["protocol_changed"].Details; d["from"] != float64(1) || d["to"] != float64(2) {
		t.Errorf("protocol_changed %+v", d)
	}
	if d := ev["capacity_changed"].Details; d["from"] != float64(5) || d["to"] != float64(3) {
		t.Errorf("capacity_changed %+v", d)
	}
	if d := ev["restarted"].Details; d["downtime_seconds"] == nil || d["downtime_seconds"].(float64) < 500 {
		t.Errorf("restarted %+v (want a downtime of about 9.5 minutes)", d)
	}
	if d := ev["online"].Details; d["offline_seconds"] == nil {
		t.Errorf("online after offline %+v", d)
	}
	tools := ev["tools_changed"].Details
	if added := tools["added"].([]any); len(added) != 1 || added[0].(map[string]any)["name"] != "semgrep" {
		t.Errorf("tools added %+v", tools)
	}
	if updated := tools["updated"].([]any); len(updated) != 1 || updated[0].(map[string]any)["to"] != "3.2.0" {
		t.Errorf("tools updated %+v", tools)
	}

	// The same heartbeat again changes nothing.
	before := len(ev)
	h.heartbeat(id, sensorapp.SensorHeartbeatData{
		Version: "0.5.0", Protocol: 2, UptimeSeconds: 60,
		UserAgent: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0",
		Report: &sensordom.CapabilityReportInput{MaxConcurrentJobs: 3, Tools: []sensordom.ReportedTool{
			tool("nuclei", "3.2.0"),
			tool("trivy", "0.60.0", sensordom.ReportedContent{Name: "trivy-db", Version: "2026-10-02T00:00:00Z", Managed: true}),
			tool("semgrep", "1.90.0"),
		}},
	})
	if ev = h.events(tid, id); len(ev) != before {
		t.Fatalf("a steady heartbeat wrote events: %+v", ev)
	}

	// Structured build members win over the User-Agent.
	h.heartbeat(id, sensorapp.SensorHeartbeatData{
		Protocol: 2, UptimeSeconds: 90, UserAgent: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0",
		Build: sensordom.BuildReport{SDKName: "openctem-sdk-go", SDKVersion: "0.9.1", SensorName: "openctemio-sensor",
			SensorVersion: "0.5.0", Commit: "ABCDEF1234", BuildTime: "2026-10-01T12:00:00Z"},
	})
	a, _ = h.svc.GetSensor(context.Background(), tid.String(), id.String())
	if sensordom.NormalizeVersion(a.Version) != "v0.5.0" || a.Build.SDKVersion != "v0.9.1" || a.Build.Commit != "abcdef1234" ||
		a.Build.BuildTime == nil || a.Build.BuildTime.Year() != 2026 {
		t.Fatalf("structured build: version %q build %+v", a.Version, a.Build)
	}

	// A filter by category.
	page, err := h.svc.ListActivity(context.Background(), sensorapp.ActivityInput{
		TenantID: tid.String(), SensorID: id.String(), Categories: []string{"status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range page.Items {
		if it.Category != sensordom.CategoryStatus {
			t.Errorf("status filter returned %s", it.Type)
		}
	}
	if len(page.Items) != 4 {
		t.Errorf("status items = %d, want online, offline, online, restarted", len(page.Items))
	}
	if _, err := h.svc.ListActivity(context.Background(), sensorapp.ActivityInput{
		TenantID: tid.String(), SensorID: id.String(), Categories: []string{"bogus"},
	}); err == nil {
		t.Error("an unknown category was accepted")
	}

	// Another tenant cannot read it.
	other := h.tenant()
	if _, err := h.svc.ListActivity(context.Background(), sensorapp.ActivityInput{TenantID: other.String(), SensorID: id.String()}); err == nil {
		t.Error("another tenant read the timeline")
	}
}

func TestSensorActivity_SDKFilterAndPolicy_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	oldSDK, newSDK, none := h.sensor(tid), h.sensor(tid), h.sensor(tid)
	h.heartbeat(oldSDK, sensorapp.SensorHeartbeatData{UserAgent: "openctemio-sensor/0.4.2 openctem-sdk-go/0.7.4"})
	h.heartbeat(newSDK, sensorapp.SensorHeartbeatData{UserAgent: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0"})
	h.heartbeat(none, sensorapp.SensorHeartbeatData{UserAgent: "sdk/1.0"})

	list := func(v *string) []shared.ID {
		res, err := h.svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{TenantID: tid.String(), SDKVersion: v, PerPage: 50})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]shared.ID, 0, len(res.Data))
		for _, s := range res.Data {
			ids = append(ids, s.ID)
		}
		return ids
	}
	v074, unknown := "v0.7.4", ""
	if got := list(&v074); len(got) != 1 || got[0] != oldSDK {
		t.Errorf("sdk_version=v0.7.4 -> %v", got)
	}
	if got := list(&unknown); len(got) != 1 || got[0] != none {
		t.Errorf("sdk_version=unknown -> %v", got)
	}
	if got := list(nil); len(got) != 3 {
		t.Errorf("no filter -> %d sensors", len(got))
	}

	policy := sensordom.HealthPolicy{SDKMinVersion: "v0.8.0", SDKLatestVersion: "v0.9.0"}.Normalized()
	now := time.Now()
	for id, want := range map[shared.ID]sensordom.SDKStatus{oldSDK: sensordom.SDKUnsupported, newSDK: sensordom.SDKCurrent, none: sensordom.SDKUnknown} {
		a, _ := h.svc.GetSensor(context.Background(), tid.String(), id.String())
		hl := a.AssessHealth(now, policy)
		if hl.SDKStatus != want {
			t.Errorf("%s: sdk status %s, want %s", a.Build.SDKVersion, hl.SDKStatus, want)
		}
		hasReason := false
		for _, r := range hl.Reasons {
			hasReason = hasReason || r.Code == sensordom.ReasonSDKUnsupported
		}
		if hasReason != (want == sensordom.SDKUnsupported) || (want == sensordom.SDKUnsupported && hl.State != sensordom.StateDegraded) {
			t.Errorf("%s: reasons %+v state %s", a.Build.SDKVersion, hl.Reasons, hl.State)
		}
	}
}
