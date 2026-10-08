// Package opsmetrics exposes the platform-wide gauges the operator's alerts
// read: sensors by health, the command queue, stuck scan runs, the
// notification outbox, the schema version and the build. See
// docs/operations/monitoring.md for the alert rules.
//
// Values are platform-wide counts with infrastructure labels only (kind,
// health, state): no tenant, sensor or run identity, so nothing about a
// tenant reaches the alert channels.
package opsmetrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/version"
)

// Source reads one snapshot of the platform-wide counts.
type Source func(ctx context.Context) (postgres.OpsSnapshot, error)

// Config configures the collector.
type Config struct {
	// ShippedSchemaVersion is the newest migration shipped with this build
	// (0 when unknown): compared with the applied version.
	ShippedSchemaVersion int64
	// SDKLatest and SDKMin are the sensor SDK policy
	// (SENSOR_SDK_LATEST_VERSION, SENSOR_SDK_MIN_VERSION).
	SDKLatest, SDKMin string
	// MaxAge is how long a snapshot is reused before the next scrape reads
	// a new one (default 30s), and Timeout bounds one read (default 5s).
	MaxAge, Timeout time.Duration
}

var (
	descUp = prometheus.NewDesc("openctem_ops_collector_up",
		"1 when the last read of the platform-wide counts succeeded", nil, nil)
	descBuild = prometheus.NewDesc("openctem_build_info",
		"The running API build (always 1)", []string{"version", "commit"}, nil)
	descSchema = prometheus.NewDesc("openctem_schema_version",
		"Database schema version: applied (in the database) and shipped (newest migration in this build)", []string{"source"}, nil)
	descSchemaDirty = prometheus.NewDesc("openctem_schema_dirty",
		"1 when the newest applied migration is marked dirty (a migration failed half way)", nil, nil)
	descSensors = prometheus.NewDesc("openctem_sensors",
		"Active sensors by kind (platform, tenant) and health", []string{"kind", "health"}, nil)
	descSensorConfig = prometheus.NewDesc("openctem_sensors_config_health",
		"Active sensors by kind and reported configuration health (ok, attention, impaired, blocked)", []string{"kind", "config_health"}, nil)
	descSensorSDK = prometheus.NewDesc("openctem_sensors_sdk",
		"Active sensors by kind and SDK status against the SDK policy (current, outdated, unsupported, unknown)", []string{"kind", "status"}, nil)
	descCommands = prometheus.NewDesc("openctem_commands",
		"Sensor commands by state: pending (due, waiting for a sensor) and running (acknowledged or running)", []string{"state"}, nil)
	descCommandOldest = prometheus.NewDesc("openctem_command_oldest_pending_seconds",
		"How long the oldest due pending command has waited for a sensor", nil, nil)
	descScanRunsOpen = prometheus.NewDesc("openctem_scan_runs_open",
		"Scan runs not finished (pending or running)", nil, nil)
	descScanRunsStuck = prometheus.NewDesc("openctem_scan_runs_past_deadline",
		"Open scan runs more than 10 minutes past their deadline (the timeout controller should have ended them)", nil, nil)
	descOutbox = prometheus.NewDesc("openctem_outbox_entries",
		"Notification outbox entries by status (pending, failed, dead)", []string{"status"}, nil)
	descOutboxOldest = prometheus.NewDesc("openctem_outbox_oldest_pending_seconds",
		"How long the oldest due pending notification has waited", nil, nil)
)

// Collector is a prometheus.Collector over the platform-wide counts. A
// scrape reuses the last snapshot while it is younger than MaxAge, so the
// database sees at most one read per MaxAge whatever the scrape rate.
type Collector struct {
	source Source
	cfg    Config
	log    *logger.Logger

	mu     sync.Mutex
	readAt time.Time
	snap   postgres.OpsSnapshot
	ok     bool
}

// New returns the collector.
func New(source Source, cfg Config, log *logger.Logger) *Collector {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Collector{source: source, cfg: cfg, log: log}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		descUp, descBuild, descSchema, descSchemaDirty, descSensors, descSensorConfig, descSensorSDK,
		descCommands, descCommandOldest, descScanRunsOpen, descScanRunsStuck, descOutbox, descOutboxOldest,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	info := version.Get()
	ch <- prometheus.MustNewConstMetric(descBuild, prometheus.GaugeValue, 1, info.Version, info.Commit)
	if c.cfg.ShippedSchemaVersion > 0 {
		ch <- prometheus.MustNewConstMetric(descSchema, prometheus.GaugeValue, float64(c.cfg.ShippedSchemaVersion), "shipped")
	}

	snap, ok := c.snapshot()
	if !ok {
		ch <- prometheus.MustNewConstMetric(descUp, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(descUp, prometheus.GaugeValue, 1)

	if snap.SchemaKnown {
		ch <- prometheus.MustNewConstMetric(descSchema, prometheus.GaugeValue, float64(snap.SchemaVersion), "applied")
		ch <- prometheus.MustNewConstMetric(descSchemaDirty, prometheus.GaugeValue, boolValue(snap.SchemaDirty))
	}

	c.collectSensors(ch, snap.Sensors)

	ch <- prometheus.MustNewConstMetric(descCommands, prometheus.GaugeValue, float64(snap.CommandsPending), "pending")
	ch <- prometheus.MustNewConstMetric(descCommands, prometheus.GaugeValue, float64(snap.CommandsRunning), "running")
	ch <- prometheus.MustNewConstMetric(descCommandOldest, prometheus.GaugeValue, snap.CommandOldestPendingSecs)
	ch <- prometheus.MustNewConstMetric(descScanRunsOpen, prometheus.GaugeValue, float64(snap.ScanRunsOpen))
	ch <- prometheus.MustNewConstMetric(descScanRunsStuck, prometheus.GaugeValue, float64(snap.ScanRunsPastDeadline))
	ch <- prometheus.MustNewConstMetric(descOutbox, prometheus.GaugeValue, float64(snap.OutboxPending), "pending")
	ch <- prometheus.MustNewConstMetric(descOutbox, prometheus.GaugeValue, float64(snap.OutboxFailed), "failed")
	ch <- prometheus.MustNewConstMetric(descOutbox, prometheus.GaugeValue, float64(snap.OutboxDead), "dead")
	ch <- prometheus.MustNewConstMetric(descOutboxOldest, prometheus.GaugeValue, snap.OutboxOldestPendingSec)
}

// sensor health values the gauge always reports (0 when none), so an alert
// on "offline > 0" has a series to read before the first sensor goes down.
var sensorHealths = []string{"online", "late", "stale", "offline", "error", "unknown"}

func (c *Collector) collectSensors(ch chan<- prometheus.Metric, rows []postgres.OpsSensorCount) {
	type key struct{ kind, value string }
	health := map[key]int64{}
	config := map[key]int64{}
	sdk := map[key]int64{}
	for _, kind := range []string{"platform", "tenant"} {
		for _, h := range sensorHealths {
			health[key{kind, h}] = 0
		}
		for _, s := range sensor.AllSDKStatuses() {
			sdk[key{kind, string(s)}] = 0
		}
	}
	for _, r := range rows {
		kind := "tenant"
		if r.Platform {
			kind = "platform"
		}
		h := r.Health
		if _, known := health[key{kind, h}]; !known {
			h = "unknown"
		}
		health[key{kind, h}] += r.Count
		if r.ConfigHealth != "" {
			config[key{kind, configHealthLabel(r.ConfigHealth)}] += r.Count
		}
		sdk[key{kind, string(sensor.ClassifySDK(r.SDKVersion, c.cfg.SDKLatest, c.cfg.SDKMin))}] += r.Count
	}
	for k, n := range health {
		ch <- prometheus.MustNewConstMetric(descSensors, prometheus.GaugeValue, float64(n), k.kind, k.value)
	}
	for k, n := range config {
		ch <- prometheus.MustNewConstMetric(descSensorConfig, prometheus.GaugeValue, float64(n), k.kind, k.value)
	}
	for k, n := range sdk {
		ch <- prometheus.MustNewConstMetric(descSensorSDK, prometheus.GaugeValue, float64(n), k.kind, k.value)
	}
}

// configHealthLabel keeps the label to the values the column allows.
func configHealthLabel(v string) string {
	switch v {
	case "ok", "attention", "impaired", "blocked":
		return v
	default:
		return "other"
	}
}

// snapshot returns the cached snapshot, reading a new one when it is older
// than MaxAge. Concurrent scrapes wait for the one read.
func (c *Collector) snapshot() (postgres.OpsSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.readAt.IsZero() && time.Since(c.readAt) < c.cfg.MaxAge {
		return c.snap, c.ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()
	snap, err := c.source(ctx)
	c.readAt = time.Now()
	if err != nil {
		c.ok = false
		if c.log != nil {
			c.log.Warn("operator metrics: reading the platform counts failed", "error", err)
		}
		return snap, false
	}
	c.snap, c.ok = snap, true
	return snap, true
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
