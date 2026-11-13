package sensorrelay

import "github.com/prometheus/client_golang/prometheus"

type metrics struct {
	envelopes    *prometheus.CounterVec
	authFailures *prometheus.CounterVec
	held         prometheus.Gauge
	polls        prometheus.Gauge
}

// newMetrics builds the relay's metrics; with a nil registerer they are
// kept but not exported. Labels carry directions and outcomes only, never
// a realm, tenant or sensor id (bounded cardinality, nothing identifying).
func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		envelopes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "openctem_relay_envelopes_total",
			Help: "Envelopes handled by the relay, by direction (up: sensor to platform, down: platform to sensor) and outcome.",
		}, []string{"direction", "outcome"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "openctem_relay_auth_failures_total",
			Help: "Requests refused because the sensor ticket or the connector certificate was not accepted.",
		}, []string{"side"}),
		held: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "openctem_relay_bytes_held",
			Help: "Envelope bytes held in the relay's mailboxes.",
		}),
		polls: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "openctem_relay_sensor_polls",
			Help: "Sensor long-polls currently open.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.envelopes, m.authFailures, m.held, m.polls)
	}
	return m
}
