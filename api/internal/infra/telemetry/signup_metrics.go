package telemetry

// Sign-up event metrics (docs/architecture/signup-activity.md). Labeled by
// kind, source and dimension only: fixed cardinality, never an email domain,
// a network prefix or a person. The prefix or domain of an alert is in the
// admin audit log.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	signupEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_signup_events_total",
		Help: "Sign-up events (kind: account_created, organization_created, access_requested; source: the sign-up path).",
	}, []string{"kind", "source"})
	signupBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_signup_burst_alerts_total",
		Help: "Sign-up burst alerts raised (dimension: ip_prefix, email_domain; kind: the event kind).",
	}, []string{"dimension", "kind"})
)

// SignupMetrics implements signupevent.Metrics.
type SignupMetrics struct{}

// ObserveSignupEvent counts one event.
func (SignupMetrics) ObserveSignupEvent(kind, source string) {
	signupEvents.WithLabelValues(kind, source).Inc()
}

// ObserveSignupBurst counts one alert.
func (SignupMetrics) ObserveSignupBurst(dimension, kind string) {
	signupBursts.WithLabelValues(dimension, kind).Inc()
}
