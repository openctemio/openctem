package metrics

// Operator metrics: signals the platform operator alerts on (panics, login
// failures, automation failures, browser errors). See
// docs/operations/monitoring.md for the alert rules built on them.
//
// Labels are infrastructure vocabulary only, from fixed sets chosen in code:
// never a tenant, user, sensor or run id, an email or a target host. Alerts
// carry these labels to Telegram/Slack, outside the platform.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// PanicsRecoveredTotal counts panics a recover() caught, by where: "http"
	// (a request handler) or the name of the background task.
	PanicsRecoveredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_panics_recovered_total",
			Help: "Panics caught by a recover(), by where (http or the background task)",
		},
		[]string{"where"},
	)

	// LoginFailuresTotal counts refused password sign-ins, by reason:
	// invalid_credentials, locked, suspended, other.
	LoginFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_auth_login_failures_total",
			Help: "Refused password sign-ins, by reason (invalid_credentials, locked, suspended, other)",
		},
		[]string{"reason"},
	)

	// LimitRefusalsTotal counts additions refused by an organization limit, by
	// limit key (seats, assets, sensors, api_keys, ci_trusts, ...).
	LimitRefusalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_limit_refusals_total",
			Help: "Additions refused by an organization limit, by limit key",
		},
		[]string{"key"},
	)

	// AutomationRunsTotal counts finished automation (workflow) runs by
	// status: completed or failed.
	AutomationRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_automation_runs_total",
			Help: "Finished automation runs, by status (completed, failed)",
		},
		[]string{"status"},
	)

	// AutomationsAutoPausedTotal counts automations the platform switched off
	// because their latest runs all failed.
	AutomationsAutoPausedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_automations_auto_paused_total",
			Help: "Automations the platform paused because their latest runs all failed",
		},
	)

	// SensorStreamOpensRefusedTotal counts sensor control-stream opens
	// refused, by reason: rate (the per-sensor open token bucket) or
	// concurrent (the per-sensor concurrent stream bound).
	SensorStreamOpensRefusedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_sensor_stream_opens_refused_total",
			Help: "Sensor control-stream opens refused, by reason (rate, concurrent)",
		},
		[]string{"reason"},
	)

	// SensorWakesCoalescedTotal counts cross-replica control-stream wakes
	// not published as they came, by reason: tenant_quota (the tenant had
	// its share of the publish queue; folded into one later tenant-wide
	// wake) or queue_full (dropped; the streams' periodic re-check delivers
	// the change).
	SensorWakesCoalescedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_sensor_wakes_coalesced_total",
			Help: "Sensor control-stream wakes not published as they came, by reason (tenant_quota, queue_full)",
		},
		[]string{"reason"},
	)

	// WebClientErrorsTotal counts errors browsers reported, by kind:
	// chunk_load, render, unhandled, other.
	WebClientErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_web_client_errors_total",
			Help: "Errors reported by the web client, by kind (chunk_load, render, unhandled, other)",
		},
		[]string{"kind"},
	)

	// SensorHeartbeatWritesTotal counts what a heartbeat wrote to Postgres
	// (docs/architecture/sensors.md, "Heartbeat soft state"), by kind: full
	// (the heartbeat changed something or brought the sensor online),
	// checkpoint (queued for the batched checkpoint), none (only the
	// liveness store), fallback (store unreachable, written to Postgres
	// under the fallback limit), dropped (store unreachable and over the
	// fallback limit).
	SensorHeartbeatWritesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_sensor_heartbeat_writes_total",
			Help: "Sensor heartbeat Postgres writes, by kind (full, checkpoint, none, fallback, dropped)",
		},
		[]string{"kind"},
	)

	// SensorLivenessDisagreementsTotal counts sensors whose ladder step from
	// the liveness store differs from the one from Postgres (shadow mode),
	// by the two steps. Zero for a week on a live install is the condition
	// to switch SENSOR_LIVENESS_STORE to redis.
	SensorLivenessDisagreementsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_sensor_liveness_disagreements_total",
			Help: "Sensors whose liveness verdict from the store differs from Postgres (shadow mode), by postgres and store step",
		},
		[]string{"postgres", "store"},
	)

	// SensorLivenessStoreErrorsTotal counts failed liveness store calls, by
	// operation (beat, touch, overdue, snapshots, generation, checkpoint).
	SensorLivenessStoreErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_sensor_liveness_store_errors_total",
			Help: "Failed sensor liveness store operations, by operation",
		},
		[]string{"op"},
	)

	// SensorLivenessRebuildsTotal counts liveness store rebuilds from the
	// Postgres checkpoint (store emptied, restarted or back after an outage).
	SensorLivenessRebuildsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_sensor_liveness_rebuilds_total",
			Help: "Sensor liveness store rebuilds from the Postgres checkpoint",
		},
	)
)

// RecordPanic counts one recovered panic. where must be a constant from
// the call site, never a value from a request or a row.
func RecordPanic(where string) {
	PanicsRecoveredTotal.WithLabelValues(where).Inc()
}
