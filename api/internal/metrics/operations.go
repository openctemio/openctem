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

	// PlanLimitRefusalsTotal counts additions refused by a plan limit, by
	// limit key (seats, assets, sensors, api_keys, ci_trusts, ...).
	PlanLimitRefusalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_plan_limit_refusals_total",
			Help: "Additions refused by a plan limit, by limit key",
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

	// WebClientErrorsTotal counts errors browsers reported, by kind:
	// chunk_load, render, unhandled, other.
	WebClientErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_web_client_errors_total",
			Help: "Errors reported by the web client, by kind (chunk_load, render, unhandled, other)",
		},
		[]string{"kind"},
	)
)

// RecordPanic counts one recovered panic. where must be a constant from
// the call site, never a value from a request or a row.
func RecordPanic(where string) {
	PanicsRecoveredTotal.WithLabelValues(where).Inc()
}
