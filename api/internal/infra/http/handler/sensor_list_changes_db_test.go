package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// pollSensors calls GET /sensors in poll mode for the harness tenant.
func (f *fleetHarness) pollSensors(query string, admin bool) (int, SensorListChangesResponse) {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors?"+query, nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, f.tenantID)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	rec := httptest.NewRecorder()
	f.sh.List(rec, req.WithContext(ctx))
	var out SensorListChangesResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			f.t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, out
}

func since(cursor string) string { return "changed_since=" + url.QueryEscape(cursor) }

// TestSensorListChanges: the poll mode of GET /sensors answers a snapshot,
// then only the sensors whose answer changed (a heartbeat, the clock moving
// the state ladder), with the stats in the same answer; another tenant's
// sensors never appear, a foreign or broken cursor yields the caller's own
// snapshot, and host details stay admin-only.
func TestSensorListChanges(t *testing.T) {
	f := newFleetHarness(t, sensordom.HealthPolicy{})
	ctx := context.Background()
	// A second sensor in this tenant and one in another tenant.
	other, err := f.sh.service.CreateSensor(ctx, sensor.CreateSensorInput{
		TenantID: f.tenantID, Name: "second-sensor", Type: "worker",
		Capabilities: []string{"sast"}, ExecutionMode: "daemon",
	})
	if err != nil {
		t.Fatalf("create second sensor: %v", err)
	}
	foreignTenant := shared.NewID()
	if _, err := f.db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		foreignTenant.String(), "poll foreign", "poll-foreign-"+foreignTenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, foreignTenant.String())
	})
	foreign, err := f.sh.service.CreateSensor(ctx, sensor.CreateSensorInput{
		TenantID: foreignTenant.String(), Name: "foreign-sensor", Type: "worker",
		Capabilities: []string{"sast"}, ExecutionMode: "daemon",
	})
	if err != nil {
		t.Fatalf("create foreign sensor: %v", err)
	}
	foreignID := foreign.Sensor.ID.String()
	ids := func(r SensorListChangesResponse) map[string]bool {
		m := map[string]bool{}
		for _, s := range r.Items {
			m[s.ID] = true
		}
		return m
	}

	// Snapshot: the whole fleet, the stats, a cursor.
	code, snap := f.pollSensors(since(""), true)
	if code != http.StatusOK || !snap.Full || snap.Total != 2 || len(snap.Items) != 2 || snap.Cursor == "" {
		t.Fatalf("snapshot: code=%d full=%v total=%d items=%d cursor=%q", code, snap.Full, snap.Total, len(snap.Items), snap.Cursor)
	}
	if snap.Stats == nil || snap.Stats.Total != 2 {
		t.Fatalf("snapshot stats = %+v, want total 2", snap.Stats)
	}
	if ids(snap)[foreignID] {
		t.Fatal("snapshot lists another tenant's sensor")
	}

	// Nothing changed: no rows, still the stats.
	_, quiet := f.pollSensors(since(snap.Cursor), true)
	if quiet.Full || len(quiet.Items) != 0 || quiet.Total != 2 || quiet.Stats == nil {
		t.Fatalf("quiet poll: full=%v items=%d total=%d stats=%v", quiet.Full, len(quiet.Items), quiet.Total, quiet.Stats != nil)
	}

	// A heartbeat changes one sensor: only that one is sent.
	f.heartbeat(map[string]any{"status": "running", "version": "0.7.0"})
	_, hb := f.pollSensors(since(quiet.Cursor), true)
	if hb.Full || len(hb.Items) != 1 || hb.Items[0].ID != f.sensorID || hb.Items[0].State == "never_connected" {
		t.Fatalf("after heartbeat: full=%v n=%d id=%s state=%s want %s", hb.Full, len(hb.Items), hb.Items[0].ID, hb.Items[0].State, f.sensorID)
	}
	if hb.Stats.ByState["never_connected"] != 1 {
		t.Errorf("stats by_state = %v, want one sensor never connected", hb.Stats.ByState)
	}

	// A write that does not touch updated_at still shows (digest of the answer).
	// The connected sensor may come along: its uptime moves with the clock.
	if _, err := f.db.ExecContext(ctx, `UPDATE sensors SET labels = '{"zone":"dmz"}'::jsonb WHERE id = $1`,
		other.Sensor.ID.String()); err != nil {
		t.Fatalf("label: %v", err)
	}
	_, lbl := f.pollSensors(since(hb.Cursor), true)
	if lbl.Full || !ids(lbl)[other.Sensor.ID.String()] {
		t.Fatalf("after label write: items=%+v", lbl.Items)
	}

	// The clock alone moves the heartbeating sensor down the ladder.
	f.sh.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, late := f.pollSensors(since(lbl.Cursor), true)
	f.sh.now = time.Now
	lateState := ""
	for _, s := range late.Items {
		if s.ID == f.sensorID {
			lateState = s.State
		}
	}
	if late.Full || lateState == "" || lateState == hb.Items[0].State {
		t.Fatalf("after two hours: full=%v state=%q items=%d", late.Full, lateState, len(late.Items))
	}

	// A sensor added to the fleet: a full snapshot.
	if _, err := f.sh.service.CreateSensor(ctx, sensor.CreateSensorInput{
		TenantID: f.tenantID, Name: "third-sensor", Type: "worker",
		Capabilities: []string{"sast"}, ExecutionMode: "daemon",
	}); err != nil {
		t.Fatalf("create third sensor: %v", err)
	}
	_, grown := f.pollSensors(since(lbl.Cursor), true)
	if !grown.Full || len(grown.Items) != 3 {
		t.Fatalf("after adding a sensor: full=%v items=%d", grown.Full, len(grown.Items))
	}

	// A cursor of another tenant's fleet (or garbage) answers this tenant's snapshot.
	foreignHarness := &fleetHarness{sensorHarness: &sensorHarness{t: t, db: f.db, tenantID: foreignTenant.String()}, sh: f.sh}
	_, fsnap := foreignHarness.pollSensors(since(""), true)
	if len(fsnap.Items) != 1 || fsnap.Items[0].ID != foreignID {
		t.Fatalf("foreign tenant snapshot = %+v", fsnap.Items)
	}
	for _, c := range []string{fsnap.Cursor, "1.!!!", "2.AAAA", "garbage"} {
		code, r := f.pollSensors(since(c), true)
		if code != http.StatusOK || !r.Full || len(r.Items) != 3 || ids(r)[foreignID] {
			t.Errorf("cursor %q: code=%d full=%v items=%d", c, code, r.Full, len(r.Items))
		}
	}

	// Host details stay admin-only in poll mode.
	if _, err := f.db.ExecContext(ctx, `UPDATE sensors SET hostname = 'build-01.internal' WHERE tenant_id = $1`, f.tenantID); err != nil {
		t.Fatalf("hostname: %v", err)
	}
	_, member := f.pollSensors(since(""), false)
	for _, s := range member.Items {
		if s.Hostname != "" {
			t.Errorf("member sees hostname %q", s.Hostname)
		}
	}

	// Poll mode is not combined with filters or paging, and the cursor is bounded.
	for _, q := range []string{since("") + "&status=active", since("") + "&page=2", since("") + "&per_page=5",
		"changed_since=1." + longCursor()} {
		if code, _ := f.pollSensors(q, true); code != http.StatusBadRequest {
			t.Errorf("%.60s: code %d, want 400", q, code)
		}
	}
}

func longCursor() string {
	b := make([]byte, maxSensorCursorLen+1)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}
