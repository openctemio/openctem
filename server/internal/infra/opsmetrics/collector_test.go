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
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func snapshot() postgres.OpsSnapshot {
	return postgres.OpsSnapshot{
		Sensors: []postgres.OpsSensorCount{
			{Platform: false, Health: "online", ConfigHealth: "ok", SDKVersion: "v0.14.0", Count: 3},
			{Platform: false, Health: "offline", ConfigHealth: "impaired", SDKVersion: "v0.8.0", Count: 2},
			{Platform: true, Health: "something-new", ConfigHealth: "weird", SDKVersion: "", Count: 1},
		},
		SensorsUnhardened: map[string]int64{"policy_none": 2, "bearer_key": 5, "tenant-1234": 9},
		CommandsPending:   4, CommandsRunning: 1, CommandOldestPendingSecs: 1800,
		ScanRunsOpen: 2, ScanRunsPastDeadline: 1,
		OutboxPending: 5, OutboxFailed: 1, OutboxDead: 7, OutboxOldestPendingSec: 90,
		SchemaVersion: 1299, SchemaKnown: true,
	}
}

func TestCollectorReportsTheSnapshot(t *testing.T) {
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { return snapshot(), nil },
		Config{ShippedSchemaVersion: 1300, SDKLatest: "v0.14.0", SDKAdvisories: []string{"v0.8.0"}}, nil)

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
	if m[`kind="tenant",status="advisory"`] != 2 || m[`kind="tenant",status="current"`] != 3 || m[`kind="platform",status="unknown"`] != 1 {
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

// openctem_sensors_unhardened reports every closed-set kind (0 when none) and
// never a label value outside it, whatever the snapshot holds.
func TestCollectorReportsUnhardenedSensors(t *testing.T) {
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { return snapshot(), nil }, Config{}, nil)
	want := `
# HELP openctem_sensors_unhardened Active tenant sensors by unhardened reason: no local policy (policy_none), platform CA not pinned (pin_none), tools without network confinement (network_unenforced), bearer key instead of a key-bound identity (bearer_key)
# TYPE openctem_sensors_unhardened gauge
openctem_sensors_unhardened{kind="bearer_key"} 5
openctem_sensors_unhardened{kind="network_unenforced"} 0
openctem_sensors_unhardened{kind="pin_none"} 0
openctem_sensors_unhardened{kind="policy_none"} 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "openctem_sensors_unhardened"); err != nil {
		t.Fatal(err)
	}
}

// The queue depth keeps closed-set labels: a stage outside the catalog is
// "other", a class outside the priorities is "other", an unknown wait is
// dropped, rows that fold into one key are summed; the tenant dimension is
// two aggregates.
func TestCollectorReportsTheQueue(t *testing.T) {
	probe, _ := stage.Lookup(stage.ProbeHTTP)
	snap := snapshot()
	snap.CommandQueue = []postgres.OpsQueueDepth{
		{Stage: probe.ID(), Tool: "httpx", Class: "high", Wait: postgres.QueueWaitReady, Count: 3},
		{Stage: probe.ID(), Tool: "httpx", Class: "high", Wait: postgres.QueueWaitHostBusy, Count: 2},
		{Stage: "tenant-secret@1", Tool: "_custom", Class: "high", Wait: postgres.QueueWaitReady, Count: 1},
		{Stage: "another-secret@2", Tool: "_custom", Class: "high", Wait: postgres.QueueWaitReady, Count: 4},
		{Stage: "", Tool: "", Class: "weird", Wait: postgres.QueueWaitScheduled, Count: 5},
		{Stage: probe.ID(), Tool: "httpx", Class: "low", Wait: "made-up", Count: 9},
	}
	snap.CommandQueueTenants, snap.CommandQueueTopTenant = 2, 7
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { return snap, nil }, Config{}, nil)
	want := `
# HELP openctem_command_queue_depth Pending sensor commands by stage, tool, priority class and why they wait (ready, host_busy, scheduled)
# TYPE openctem_command_queue_depth gauge
openctem_command_queue_depth{class="high",stage="` + probe.ID() + `",tool="httpx",wait="host_busy"} 2
openctem_command_queue_depth{class="high",stage="` + probe.ID() + `",tool="httpx",wait="ready"} 3
openctem_command_queue_depth{class="high",stage="other",tool="_custom",wait="ready"} 5
openctem_command_queue_depth{class="other",stage="none",tool="none",wait="scheduled"} 5
# HELP openctem_command_queue_tenants Tenants with at least one pending sensor command
# TYPE openctem_command_queue_tenants gauge
openctem_command_queue_tenants 2
# HELP openctem_command_queue_top_tenant_pending Pending sensor commands of the tenant with the most (a fairness signal; no tenant identity)
# TYPE openctem_command_queue_top_tenant_pending gauge
openctem_command_queue_top_tenant_pending 7
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"openctem_command_queue_depth", "openctem_command_queue_tenants", "openctem_command_queue_top_tenant_pending"); err != nil {
		t.Fatal(err)
	}
}

// SDKLatestFunc is read on every scrape, so a newer SDK learned from the
// release feed turns current sensors into outdated ones without a restart.
func TestCollectorReadsTheLatestSDKPerScrape(t *testing.T) {
	latest := "v0.14.0"
	c := New(func(context.Context) (postgres.OpsSnapshot, error) { return snapshot(), nil },
		Config{SDKLatest: "v0.1.0", SDKLatestFunc: func() string { return latest }, SDKAdvisories: []string{"v0.8.0"}, MaxAge: time.Nanosecond}, nil)
	if m := gather(t, c, "openctem_sensors_sdk"); m[`kind="tenant",status="current"`] != 3 {
		t.Fatalf("sdk statuses = %v", m)
	}
	latest = "v0.15.0"
	if m := gather(t, c, "openctem_sensors_sdk"); m[`kind="tenant",status="outdated"`] != 3 {
		t.Fatalf("sdk statuses after a newer SDK = %v", m)
	}
}
