package metrics

// Metrics for the browser real-time socket (/api/v1/ws).
//
// Design: docs/rfcs/RFC-045-websocket-auth.md. They answer "are sockets being
// closed when sessions end?" and "is anyone being refused or throttled?"
// without reading logs. Labels are bounded enums, never ids.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// WSConnections is the number of open sockets on this instance.
	WSConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "openctem_ws_connections",
			Help: "Open real-time WebSocket connections on this API instance",
		},
	)

	// WSConnectsTotal counts accepted upgrades.
	WSConnectsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_ws_connects_total",
			Help: "Real-time WebSocket upgrades accepted",
		},
	)

	// WSUpgradeRejectionsTotal counts upgrades refused by the socket handler
	// itself. reason: origin | no_identity | session_revoked | too_many.
	// Authentication and tenant-gate refusals are counted by the HTTP
	// middleware metrics for the route.
	WSUpgradeRejectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_ws_upgrade_rejections_total",
			Help: "Real-time WebSocket upgrades refused by the socket handler",
		},
		[]string{"reason"},
	)

	// WSForcedClosesTotal counts sockets the server closed on its own.
	// reason: session_expired | session_revoked | access_changed |
	// rate_limited | shutdown.
	WSForcedClosesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_ws_forced_closes_total",
			Help: "Real-time WebSocket connections closed by the server",
		},
		[]string{"reason"},
	)

	// WSSubscribeDeniedTotal counts subscribe requests refused by channel
	// authorization.
	WSSubscribeDeniedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_ws_subscribe_denied_total",
			Help: "Real-time WebSocket channel subscriptions refused",
		},
	)

	// WSMessagesThrottledTotal counts client messages dropped by the
	// per-connection rate limit.
	WSMessagesThrottledTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_ws_messages_throttled_total",
			Help: "Client WebSocket messages dropped by the per-connection rate limit",
		},
	)
)
