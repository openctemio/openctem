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
		[]string{"tenant_id", "reason"},
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
		[]string{"tenant_id"},
	)

	// AITriageBudgetUsedTokens is the per-tenant running token
	// counter for the current billing period. Gauge (not counter)
	// because the value resets to 0 at month rollover. Emit from
	// BudgetService.Record() each time a triage finishes.
	AITriageBudgetUsedTokens = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openctem_security_ai_triage_budget_used_tokens",
			Help: "LLM tokens consumed by a tenant in the current billing period",
		},
		[]string{"tenant_id"},
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
		[]string{"tenant_id"},
	)
)
