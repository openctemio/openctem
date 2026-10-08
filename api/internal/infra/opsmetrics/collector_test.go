package opsmetrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

func snapshot() postgres.OpsSnapshot {
	return postgres.OpsSnapshot{
		Sensors: []postgres.OpsSensorCount{
			{Platform: false, Health: "online", ConfigHealth: "ok", SDKVersion: "v0.14.0", Count: 3},
			{Platform: false, Health: "offline", ConfigHealth: "impaired", SDKVersion: "v0.8.0", Count: 2},
			{Platform: true, Health: "something-new", ConfigHealth: "weird", SDKVersion: "", Count: 1},
		},
		CommandsPending: 4, CommandsRunning: 1, CommandOldestPendingSecs: 1800,
		ScanRunsOpen: 2, ScanRunsPastDeadline: 1,
		OutboxPending: 5, OutboxFailed: 1, OutboxDead: 7, OutboxOldestPendingSec: 90,
		SchemaVersion: 1299, SchemaKnown: true,
	}
}

func TestCollectorReportsTheSnapshot(t *testing.T) {
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { return snapshot(), nil },
		Config{ShippedSchemaVersion: 1300, SDKLatest: "v0.14.0", SDKMin: "v0.9.0"}, nil)

	want := `
# HELP openctem_commands Sensor commands by state: pending (due, waiting for a sensor) and running (acknowledged or running)
# TYPE openctem_commands gauge
openctem_commands{state="pending"} 4
openctem_commands{state="running"} 1
# HELP openctem_schema_version Database schema version: applied (in the database) and shipped (newest migration in this build)
# TYPE openctem_schema_version gauge
openctem_schema_version{source="applied"} 1299
openctem_schema_version{source="shipped"} 1300
# HELP openctem_scan_runs_past_deadline Open scan runs more than 10 minutes past their deadline (the timeout controller should have ended them)
# TYPE openctem_scan_runs_past_deadline gauge
openctem_scan_runs_past_deadline 1
# HELP openctem_outbox_entries Notification outbox entries by status (pending, failed, dead)
# TYPE openctem_outbox_entries gauge
openctem_outbox_entries{status="dead"} 7
openctem_outbox_entries{status="failed"} 1
openctem_outbox_entries{status="pending"} 5
# HELP openctem_ops_collector_up 1 when the last read of the platform-wide counts succeeded
# TYPE openctem_ops_collector_up gauge
openctem_ops_collector_up 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"openctem_commands", "openctem_schema_version", "openctem_scan_runs_past_deadline",
		"openctem_outbox_entries", "openctem_ops_collector_up"); err != nil {
		t.Fatal(err)
	}

	sensors := `
# HELP openctem_sensors Active sensors by kind (platform, tenant) and health
# TYPE openctem_sensors gauge
openctem_sensors{health="error",kind="platform"} 0
openctem_sensors{health="error",kind="tenant"} 0
openctem_sensors{health="late",kind="platform"} 0
openctem_sensors{health="late",kind="tenant"} 0
openctem_sensors{health="offline",kind="platform"} 0
openctem_sensors{health="offline",kind="tenant"} 2
openctem_sensors{health="online",kind="platform"} 0
openctem_sensors{health="online",kind="tenant"} 3
openctem_sensors{health="stale",kind="platform"} 0
openctem_sensors{health="stale",kind="tenant"} 0
openctem_sensors{health="unknown",kind="platform"} 1
openctem_sensors{health="unknown",kind="tenant"} 0
# HELP openctem_sensors_config_health Active sensors by kind and reported configuration health (ok, attention, impaired, blocked)
# TYPE openctem_sensors_config_health gauge
openctem_sensors_config_health{config_health="impaired",kind="tenant"} 2
openctem_sensors_config_health{config_health="ok",kind="tenant"} 3
openctem_sensors_config_health{config_health="other",kind="platform"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(sensors), "openctem_sensors", "openctem_sensors_config_health"); err != nil {
		t.Fatal(err)
	}

	m := gather(t, c, "openctem_sensors_sdk")
	if m[`kind="tenant",status="unsupported"`] != 2 || m[`kind="tenant",status="current"`] != 3 || m[`kind="platform",status="unknown"`] != 1 {
		t.Fatalf("sdk statuses = %v", m)
	}
}

// The database is read at most once per MaxAge, whatever the scrape rate.
func TestCollectorCachesTheSnapshot(t *testing.T) {
	calls := 0
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { calls++; return snapshot(), nil },
		Config{MaxAge: time.Hour}, nil)
	for i := 0; i < 5; i++ {
		testutil.CollectAndCount(c)
	}
	if calls != 1 {
		t.Fatalf("source read %d times, want 1", calls)
	}
}

// A failed read reports up=0 and none of the counts (no stale zeros that
// would resolve an alert).
func TestCollectorReportsAFailedRead(t *testing.T) {
	c := New(func(context.Context) (postgres.OpsSnapshot, error) {
		return postgres.OpsSnapshot{}, errors.New("db down")
	}, Config{}, nil)
	if got := gather(t, c, "openctem_ops_collector_up")[""]; got != 0 {
		t.Fatalf("up = %v, want 0", got)
	}
	if n := testutil.CollectAndCount(c, "openctem_commands", "openctem_sensors"); n != 0 {
		t.Fatalf("%d count series reported after a failed read, want 0", n)
	}
}

// gather returns one metric family's values keyed by their rendered labels.
func gather(t *testing.T, c prometheus.Collector, name string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			parts := make([]string, 0, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				parts = append(parts, l.GetName()+`="`+l.GetValue()+`"`)
			}
			out[strings.Join(parts, ",")] = m.GetGauge().GetValue()
		}
	}
	return out
}
