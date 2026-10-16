package metrics

// Metrics for the platform's security defences.
//
// These counters and gauges surface the defence-in-depth primitives
// added in the 2026-04 security audit pass so operators can answer
// "is the defence actually catching anything?" without reading logs.
//
// Each series name starts with `openctem_security_` so Grafana
// dashboards can slurp them with a single prefix match.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// -----------------------------------------------------------------
// CSRF
// -----------------------------------------------------------------

var (
	// CSRFRejectionsTotal counts requests rejected by the CSRF
	// middleware (cookie missing, header missing, or mismatched
	// token). "reason" labels: missing_cookie | missing_header |
	// token_mismatch. Route method is labelled separately so a
	// spike on one endpoint doesn't get lost in the platform total.
	//
	// Emit from api/internal/infra/http/middleware/csrf.go at each
	// reject-branch.
	CSRFRejectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_security_csrf_rejections_total",
			Help: "HTTP requests rejected by the CSRF double-submit middleware",
		},
		[]string{"reason", "method"},
	)
)

// -----------------------------------------------------------------
// Audit-log hash chain (mig 000154)
// -----------------------------------------------------------------

var (
	// AuditChainBreaksTotal counts chain breaks discovered by the
	// AuditChainVerifyController (runs hourly). An increase here is
	// the SIEM's primary signal that someone tampered with the
	// audit_logs table.
	AuditChainBreaksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_security_audit_chain_breaks_total",
			Help: "Audit-log hash-chain breaks detected by the scheduled verifier",
		},
		[]string{"reason"},
	)

	// AuditChainVerifyRunsTotal counts controller reconcile passes.
	// Used to alert if the verifier has stopped running: if this
	// series is flat for >1h the controller is stuck.
	AuditChainVerifyRunsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_security_audit_chain_verify_runs_total",
			Help: "Scheduled audit-chain verifier reconcile invocations",
		},
	)
)

// -----------------------------------------------------------------
// AI-triage validator + budget (RFC-008)
// -----------------------------------------------------------------

var (
	// AITriageNeedsReviewTotal counts triage results whose LLM
	// output failed validator sanity checks (invalid severity enum,
	// coerced default, prompt-injection suspected). Non-zero means
	// the human-review queue has items.
	AITriageNeedsReviewTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_security_ai_triage_needs_review_total",
			Help: "AI-triage results flagged for human review due to validator warnings",
		},
		[]string{},
	)

	// AITriageBudgetExhaustedTotal counts triage calls refused
	// because the tenant hit its monthly ceiling. A spike is
	// user-visible (triage no longer runs) but the metric feeds
	// ops dashboards for capacity planning.
	AITriageBudgetExhaustedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_security_ai_triage_budget_exhausted_total",
			Help: "Triage calls refused because the tenant's monthly token budget is exhausted",
		},
		[]string{},
	)
)

// -----------------------------------------------------------------
// Admin audit sink (off-box copy of admin_audit_logs)
// -----------------------------------------------------------------

var (
	// AdminAuditForwardRows counts rows the sinks acknowledged.
	AdminAuditForwardRows = promauto.NewCounter(prometheus.CounterOpts{
		Name: "openctem_admin_audit_forward_rows_total",
		Help: "Admin audit rows acknowledged by the off-box sinks",
	})
	// AdminAuditForwardFailures counts failed deliveries by sink.
	AdminAuditForwardFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_admin_audit_forward_failures_total",
		Help: "Failed admin audit forward attempts by sink (webhook, syslog, file, store)",
	}, []string{"sink"})
	// AdminAuditForwardConsecutiveFailures is the current failure streak; alert when above 0 for several minutes.
	AdminAuditForwardConsecutiveFailures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_admin_audit_forward_consecutive_failures",
		Help: "Consecutive failed admin audit forward runs (0 when healthy)",
	})
	// AdminAuditForwardLagRows is chain head minus the acknowledged cursor.
	AdminAuditForwardLagRows = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_admin_audit_forward_lag_rows",
		Help: "Admin audit rows written but not yet acknowledged by the sinks",
	})
	// AdminAuditForwardLagSeconds is the age of the oldest unsent row.
	AdminAuditForwardLagSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_admin_audit_forward_lag_seconds",
		Help: "Age of the oldest admin audit row not yet acknowledged by the sinks",
	})
	// AdminAuditForwardLastSuccess is a unix time; alert when it stops moving.
	AdminAuditForwardLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_admin_audit_forward_last_success_timestamp_seconds",
		Help: "Unix time of the last admin audit forward run that finished without error",
	})
	// AdminAuditChainOK is 1 while the last verification passed, 0 on a break.
	AdminAuditChainOK = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_admin_audit_chain_ok",
		Help: "1 when the last admin audit chain verification passed, 0 when it found a break",
	})
	// AdminAuditChainBreaks counts breaks when a verification first fails.
	AdminAuditChainBreaks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "openctem_admin_audit_chain_breaks_total",
		Help: "Admin audit chain breaks found by the forwarder's verification",
	})
	// AdminAuditChainVerifyErrors counts verifications that could not run.
	AdminAuditChainVerifyErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "openctem_admin_audit_chain_verify_errors_total",
		Help: "Admin audit chain verifications that failed to run",
	})
)
