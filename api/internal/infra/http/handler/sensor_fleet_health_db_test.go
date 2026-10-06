package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// fleetHarness drives the management API (GET /sensors, /sensors/{id},
// /sensors/stats) next to a sensor that heartbeats for real.
type fleetHarness struct {
	*sensorHarness
	sh *SensorHandler
}

func newFleetHarness(t *testing.T, policy sensordom.HealthPolicy) *fleetHarness {
	t.Helper()
	h := newSensorHarness(t)
	sh := NewSensorHandler(
		sensor.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop()),
		validator.New(), logger.NewNop())
	sh.SetHealthPolicy(policy)
	return &fleetHarness{sensorHarness: h, sh: sh}
}

func (f *fleetHarness) call(fn http.HandlerFunc, path, id string) map[string]json.RawMessage {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, f.tenantID)
	if id != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		f.t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		f.t.Fatalf("decode %s: %v", path, err)
	}
	return raw
}

func (f *fleetHarness) get() (SensorResponse, map[string]json.RawMessage) {
	f.t.Helper()
	raw := f.call(f.sh.Get, "/api/v1/sensors/"+f.sensorID, f.sensorID)
	b, _ := json.Marshal(raw)
	var s SensorResponse
	if err := json.Unmarshal(b, &s); err != nil {
		f.t.Fatalf("decode sensor: %v", err)
	}
	return s, raw
}

func (f *fleetHarness) stats() SensorStatsResponse {
	f.t.Helper()
	raw := f.call(f.sh.GetStats, "/api/v1/sensors/stats", "")
	b, _ := json.Marshal(raw)
	var s SensorStatsResponse
	if err := json.Unmarshal(b, &s); err != nil {
		f.t.Fatalf("decode stats: %v", err)
	}
	return s
}

func (f *fleetHarness) listed() (int, SensorResponse) {
	f.t.Helper()
	raw := f.call(f.sh.List, "/api/v1/sensors", "")
	var items []SensorResponse
	if err := json.Unmarshal(raw["items"], &items); err != nil {
		f.t.Fatalf("decode items: %v", err)
	}
	var total int
	_ = json.Unmarshal(raw["total"], &total)
	for _, s := range items {
		if s.ID == f.sensorID {
			return total, s
		}
	}
	f.t.Fatal("sensor missing from the list")
	return 0, SensorResponse{}
}

func reasonCodes(rs []SensorHealthReasonResponse) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Code] = true
	}
	return out
}

// TestSensorFleetHealth_ResponseFields: the computed state ladder, health
// reasons, normalized version and release channel, uptime, key expiry and
// offline/error times reach GET /sensors/{id}, GET /sensors and
// GET /sensors/stats, and the stats count the same sensors as the list.
func TestSensorFleetHealth_ResponseFields(t *testing.T) {
	f := newFleetHarness(t, sensordom.HealthPolicy{LatestVersion: "v0.8.0", MinVersion: "v0.4.0"})

	// Before the first heartbeat.
	s, raw := f.get()
	if s.State != "never_connected" || s.VersionStatus != "unknown" {
		t.Fatalf("before heartbeat: state=%q version_status=%q", s.State, s.VersionStatus)
	}
	for _, k := range []string{"health_reasons"} {
		if string(raw[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, raw[k])
		}
	}
	for _, k := range []string{"key_expires_at", "uptime_seconds", "started_at", "last_offline_at", "last_error_at"} {
		if v, ok := raw[k]; !ok || string(v) != "null" {
			t.Errorf("%s = %s (present=%v), want null", k, v, ok)
		}
	}

	// A heartbeat with version, uptime and a healthy outbox.
	f.heartbeat(map[string]any{
		"status": "running", "version": "0.7.0", "uptime_seconds": 7200,
		"outbox": map[string]any{"pending_count": 0},
	})
	s, _ = f.get()
	if s.State != "online" || len(s.HealthReasons) != 0 {
		t.Errorf("after heartbeat: state=%q reasons=%v", s.State, s.HealthReasons)
	}
	if s.Version != "v0.7.0" || s.VersionStatus != "update_available" {
		t.Errorf("version=%q status=%q, want v0.7.0 update_available", s.Version, s.VersionStatus)
	}
	if s.UptimeSeconds == nil || *s.UptimeSeconds < 7198 || *s.UptimeSeconds > 7202 || s.StartedAt == nil {
		t.Errorf("uptime=%v started_at=%v, want ~7200", s.UptimeSeconds, s.StartedAt)
	}

	// Results the platform refused: degraded, with the reason.
	f.heartbeat(map[string]any{
		"status": "running", "outbox": map[string]any{"pending_count": 4, "dead_letter_count": 2},
	})
	s, _ = f.get()
	if s.State != "degraded" || !reasonCodes(s.HealthReasons)["outbox_dead_letters"] {
		t.Errorf("dead letters: state=%q reasons=%v", s.State, s.HealthReasons)
	}
	for _, r := range s.HealthReasons {
		if r.Severity == "" || r.Message == "" {
			t.Errorf("reason without severity or message: %+v", r)
		}
	}

	// Key expiry, offline and error times come from the row.
	exp := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	if _, err := f.db.ExecContext(context.Background(),
		`UPDATE sensors SET key_expires_at = $2, last_offline_at = NOW() - interval '1 day', last_error_at = NOW() - interval '2 hours' WHERE id = $1`,
		f.sensorID, exp); err != nil {
		t.Fatalf("set key expiry: %v", err)
	}
	s, _ = f.get()
	if s.KeyExpiresAt == nil || *s.KeyExpiresAt != exp.Format(time.RFC3339) {
		t.Errorf("key_expires_at = %v, want %s", s.KeyExpiresAt, exp.Format(time.RFC3339))
	}
	if !reasonCodes(s.HealthReasons)["key_expiring"] {
		t.Errorf("key expiring in 3 days not reported: %v", s.HealthReasons)
	}
	if s.LastOfflineAt == nil || s.LastErrorAt == nil {
		t.Errorf("last_offline_at=%v last_error_at=%v", s.LastOfflineAt, s.LastErrorAt)
	}

	// The list carries the same computed fields.
	total, l := f.listed()
	if l.State != s.State || l.VersionStatus != s.VersionStatus || len(l.HealthReasons) != len(s.HealthReasons) {
		t.Errorf("list differs from detail: %+v vs %+v", l, s)
	}

	// Stats: same population as the list, the state breakdown, the channel.
	st := f.stats()
	if st.Total != total {
		t.Errorf("stats total %d != list total %d", st.Total, total)
	}
	if st.ByState["degraded"] != 1 || st.NeedsAttention != 1 {
		t.Errorf("by_state=%v needs_attention=%d", st.ByState, st.NeedsAttention)
	}
	if st.ByVersionStatus["update_available"] != 1 {
		t.Errorf("by_version_status=%v", st.ByVersionStatus)
	}
	if st.LatestVersion != "v0.8.0" || st.MinVersion != "v0.4.0" {
		t.Errorf("channel latest=%q min=%q", st.LatestVersion, st.MinVersion)
	}
	if st.OnlineWindowSeconds != 40 || st.OfflineAfterSeconds != 300 { // 30s idle interval + 10s grace
		t.Errorf("windows online=%d offline=%d", st.OnlineWindowSeconds, st.OfflineAfterSeconds)
	}
	if st.CanTakeJobs != 1 || st.JobSlots != 5 {
		t.Errorf("can_take_jobs=%d job_slots=%d", st.CanTakeJobs, st.JobSlots)
	}
	for _, state := range sensordom.AllStates() {
		if _, ok := st.ByState[string(state)]; !ok {
			t.Errorf("by_state is missing %q (every state is listed, zeros included)", state)
		}
	}
}

// TestSensorFleetHealth_ClientIPBehindGateway: behind a trusted proxy (the
// built-in gateway sets X-Real-IP) the heartbeat stores the sensor's address,
// not the proxy's; from an untrusted peer the header is ignored.
func TestSensorFleetHealth_ClientIPBehindGateway(t *testing.T) {
	f := newFleetHarness(t, sensordom.HealthPolicy{})
	t.Cleanup(func() { SetAuthTrustedProxies(nil) })

	f.header = http.Header{"X-Real-Ip": {"203.0.113.10"}, "X-Forwarded-For": {"203.0.113.10"}}

	SetAuthTrustedProxies(nil)
	f.heartbeat(map[string]any{"status": "running"})
	if s, _ := f.get(); s.IPAddress != "127.0.0.1" {
		t.Errorf("untrusted peer: ip = %q, want the peer 127.0.0.1", s.IPAddress)
	}

	SetAuthTrustedProxies(httpsec.NewTrustedProxySet([]string{"127.0.0.0/8"}))
	f.heartbeat(map[string]any{"status": "running"})
	if s, _ := f.get(); s.IPAddress != "203.0.113.10" {
		t.Errorf("trusted gateway: ip = %q, want 203.0.113.10", s.IPAddress)
	}
}
