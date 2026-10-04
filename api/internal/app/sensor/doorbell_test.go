package sensor

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeWork struct {
	work  sensordom.PendingWork
	err   error
	delay time.Duration
	calls int
	limit int
	caps  []string
}

func (f *fakeWork) PendingWorkForSensor(ctx context.Context, _, _ shared.ID, caps []string, limit int) (sensordom.PendingWork, error) {
	f.calls++
	f.limit = limit
	f.caps = caps
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return sensordom.PendingWork{}, ctx.Err()
		}
	}
	return f.work, f.err
}

func testSensor() *sensordom.Sensor {
	tenant := shared.NewID()
	return &sensordom.Sensor{
		ID: shared.NewID(), TenantID: &tenant, Status: sensordom.SensorStatusActive,
		Capabilities: []string{"sast", "dast"}, Tools: []string{"semgrep", "nuclei"},
		ExecutionMode: sensordom.ExecutionModeDaemon, MaxConcurrentJobs: 5,
		Config: map[string]any{"b": 1, "a": "x"},
	}
}

func newTestDoorbell(src PendingWorkSource) *Doorbell {
	return NewDoorbell(src, DefaultDoorbellConfig().Normalized(5*time.Minute), logger.NewNop())
}

func TestDoorbell_IdleLegacySensorGetsNoHints(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{ZoneFingerprint: "z1@1"}}
	h := newTestDoorbell(src).Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor()}})
	if !reflect.DeepEqual(h, sensordom.HeartbeatHints{}) {
		t.Fatalf("idle v1 sensor got hints %+v; want none, so its response stays byte-identical", h)
	}
	if src.calls != 1 {
		t.Fatalf("doorbell ran %d queries, want exactly 1", src.calls)
	}
}

func TestDoorbell_PendingWorkRingsWithShortInterval(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{Count: 3}}
	a := testSensor()
	h := newTestDoorbell(src).Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: a}})
	if h.PendingJobs != 3 || h.NextHeartbeatSeconds != 5 {
		t.Fatalf("got pending=%d next=%d, want 3 and the 5s busy interval", h.PendingJobs, h.NextHeartbeatSeconds)
	}
	if h.ConfigVersion != "" || len(h.Actions) != 0 {
		t.Fatalf("legacy sensor got config_version/actions it did not ask for: %+v", h)
	}
	if src.limit != 100 {
		t.Errorf("count cap passed to the query = %d, want 100", src.limit)
	}
	if !reflect.DeepEqual(src.caps, a.Capabilities) {
		t.Errorf("query got capabilities %v, want the sensor's %v (same gate as the poll)", src.caps, a.Capabilities)
	}
}

// A command the sensor claimed was canceled: it may still be running it, so it
// rings again soon and gets the cancel within the busy interval, not after an
// idle one. Nothing is pending, so it is not told there is work.
func TestDoorbell_RecentlyCanceledRingsWithShortInterval(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{RecentlyCanceled: 1}}
	h := newTestDoorbell(src).Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor()}})
	if h.PendingJobs != 0 || h.NextHeartbeatSeconds != 5 {
		t.Fatalf("got pending=%d next=%d, want 0 and the 5s busy interval", h.PendingJobs, h.NextHeartbeatSeconds)
	}
}

func TestDoorbell_SlowQueryAdvisesLoadedInterval(t *testing.T) {
	cfg := DefaultDoorbellConfig()
	cfg.SlowQuery = 20 * time.Millisecond
	d := NewDoorbell(&fakeWork{delay: 30 * time.Millisecond}, cfg.Normalized(5*time.Minute), logger.NewNop())
	h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor()}})
	if h.NextHeartbeatSeconds != 120 {
		t.Fatalf("next = %d after a slow doorbell query, want the 120s loaded interval", h.NextHeartbeatSeconds)
	}
}

func TestDoorbell_QueryFailureOmitsHintsButKeepsActions(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	for name, src := range map[string]*fakeWork{
		"error":   {err: errors.New("connection refused\ninjected line")},
		"timeout": {delay: 2 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultDoorbellConfig()
			cfg.QueryTimeout = 20 * time.Millisecond
			d := NewDoorbell(src, cfg.Normalized(5*time.Minute), logger.NewNop())
			h := d.Ring(context.Background(), DoorbellRequest{
				Identity: SensorIdentity{Sensor: testSensor(), KeyExpiresAt: &exp}, Aware: true,
			})
			if h.PendingJobs != 0 || h.ConfigVersion != "" || h.NextHeartbeatSeconds != 0 {
				t.Fatalf("query %s: got query-derived hints %+v; want them omitted", name, h)
			}
			if !reflect.DeepEqual(h.Actions, []sensordom.Action{sensordom.ActionRotateKey}) {
				t.Fatalf("query %s: actions = %v; want rotate_key, which needs no query", name, h.Actions)
			}
		})
	}
}

func TestDoorbell_PausedSensor(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{Count: 9}}
	h := newTestDoorbell(src).Ring(context.Background(), DoorbellRequest{
		Identity: SensorIdentity{Sensor: testSensor(), Paused: true}, Aware: true,
	})
	want := sensordom.HeartbeatHints{Actions: []sensordom.Action{sensordom.ActionPause}, NextHeartbeatSeconds: 30}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("paused sensor got %+v, want %+v", h, want)
	}
	if src.calls != 0 {
		t.Fatal("a paused sensor may take no work; the doorbell must not even count it")
	}
}

func TestDoorbell_RotateKeyWindow(t *testing.T) {
	d := newTestDoorbell(&fakeWork{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	cases := []struct {
		name string
		exp  *time.Time
		want bool
	}{
		{"never expires", nil, false},
		{"outside window", ptrTime(now.Add(25 * time.Hour)), false},
		{"at the window edge", ptrTime(now.Add(24 * time.Hour)), true},
		{"inside window", ptrTime(now.Add(time.Hour)), true},
	}
	for _, c := range cases {
		h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor(), KeyExpiresAt: c.exp}})
		got := reflect.DeepEqual(h.Actions, []sensordom.Action{sensordom.ActionRotateKey})
		if got != c.want {
			t.Errorf("%s: actions = %v, want rotate_key=%v", c.name, h.Actions, c.want)
		}
	}

	off := DefaultDoorbellConfig()
	off.KeyRenewBefore = 0
	d = NewDoorbell(&fakeWork{}, off, logger.NewNop())
	if h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor(), KeyExpiresAt: ptrTime(time.Now())}}); len(h.Actions) != 0 {
		t.Errorf("rotate_key rung with the window disabled: %v", h.Actions)
	}
}

func TestDoorbell_AwareSensorAlwaysGetsVersionAndInterval(t *testing.T) {
	h := newTestDoorbell(&fakeWork{}).Ring(context.Background(), DoorbellRequest{
		Identity: SensorIdentity{Sensor: testSensor()}, Aware: true,
	})
	if h.ConfigVersion == "" || h.NextHeartbeatSeconds != 30 || h.PendingJobs != 0 {
		t.Fatalf("aware idle sensor got %+v; want a config_version and the 30s idle interval", h)
	}
}

func TestDoorbell_PlatformSensorSkipsTheQuery(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{Count: 5}}
	a := testSensor()
	a.TenantID = nil
	a.IsPlatformSensor = true
	h := newTestDoorbell(src).Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: a}, Aware: true})
	if src.calls != 0 || h.PendingJobs != 0 {
		t.Fatalf("platform sensor: %d queries, pending %d; it does not use the tenant poll", src.calls, h.PendingJobs)
	}
	if h.ConfigVersion == "" {
		t.Error("platform sensor should still get a config_version")
	}
}

func TestConfigVersion_StableAndSensitive(t *testing.T) {
	a := testSensor()
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	base := ConfigVersion(a, &exp, "z1@1")
	if len(base) != 16 {
		t.Fatalf("config_version %q, want 16 hex chars", base)
	}

	same := *a
	same.Capabilities = []string{"dast", "sast"} // order does not matter
	same.Tools = []string{"nuclei", "semgrep"}
	same.CPUPercent, same.MemoryPercent, same.CurrentJobs = 99, 99, 4 // metrics are not config
	now := time.Now()
	same.LastSeenAt, same.UpdatedAt = &now, now
	if got := ConfigVersion(&same, &exp, "z1@1"); got != base {
		t.Errorf("config_version changed on reorder/metrics: %s -> %s", base, got)
	}

	changes := map[string]func() string{
		"tools": func() string {
			b := *a
			b.Tools = []string{"semgrep"}
			return ConfigVersion(&b, &exp, "z1@1")
		},
		"capabilities": func() string {
			b := *a
			b.Capabilities = []string{"sast"}
			return ConfigVersion(&b, &exp, "z1@1")
		},
		"max jobs": func() string {
			b := *a
			b.MaxConcurrentJobs = 6
			return ConfigVersion(&b, &exp, "z1@1")
		},
		"config": func() string {
			b := *a
			b.Config = map[string]any{"a": "y", "b": 1}
			return ConfigVersion(&b, &exp, "z1@1")
		},
		"key expiry":    func() string { e := exp.Add(time.Hour); return ConfigVersion(a, &e, "z1@1") },
		"no key expiry": func() string { return ConfigVersion(a, nil, "z1@1") },
		"zones":         func() string { return ConfigVersion(a, &exp, "z1@1,z2@1") },
		"zone changed":  func() string { return ConfigVersion(a, &exp, "z1@2") },
	}
	for name, f := range changes {
		if f() == base {
			t.Errorf("config_version did not change when %s changed", name)
		}
	}
}

func TestDoorbellConfig_Normalized(t *testing.T) {
	c := DoorbellConfig{}.Normalized(5 * time.Minute)
	if c.MaxInterval != 150*time.Second {
		t.Errorf("max = %v, want 150s: half of the 5m offline timeout", c.MaxInterval)
	}
	if c.MinInterval != 5*time.Second || c.IdleInterval != 30*time.Second || c.BusyInterval != 5*time.Second ||
		c.LoadedInterval != 120*time.Second || c.PendingCap != 100 {
		t.Errorf("zero config did not take the defaults: %+v", c)
	}

	d := NewDoorbell(&fakeWork{work: sensordom.PendingWork{Count: 1}}, DoorbellConfig{
		IdleInterval: time.Hour, BusyInterval: time.Millisecond, MinInterval: 5 * time.Second, MaxInterval: time.Hour,
	}.Normalized(2*time.Minute), logger.NewNop())
	if got := d.seconds(time.Hour); got != 60 {
		t.Errorf("an hour clamps to %ds, want 60 (half the 2m offline timeout)", got)
	}
	if got := d.seconds(time.Millisecond); got != 5 {
		t.Errorf("1ms clamps to %ds, want the 5s floor", got)
	}

	tiny := DoorbellConfig{MinInterval: 10 * time.Second, MaxInterval: time.Second}.Normalized(0)
	if tiny.MaxInterval < tiny.MinInterval {
		t.Errorf("max %v below min %v", tiny.MaxInterval, tiny.MinInterval)
	}
}

func TestAction_ClosedSet(t *testing.T) {
	want := []string{"pause", "resume", "drain", "rotate_key", "update"}
	got := make([]string, 0, len(want))
	for _, a := range sensordom.Actions() {
		if !a.IsValid() {
			t.Errorf("%q not valid", a)
		}
		got = append(got, string(a))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
	for _, bad := range []sensordom.Action{"", "shell", "exec", "PAUSE", "run:rm -rf /"} {
		if bad.IsValid() {
			t.Errorf("%q accepted; the action set is closed (RFC-023 R-4)", bad)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
