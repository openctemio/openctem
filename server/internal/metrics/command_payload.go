package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
)

// CommandPayloadRefusedTotal counts commands refused at creation because
// their payload is over command.MaxPayloadBytes.
var CommandPayloadRefusedTotal = promauto.NewCounterFunc(
	prometheus.CounterOpts{
		Name: "command_payload_refused_total",
		Help: "Commands refused at creation because their payload is over the size cap (4 MiB)",
	},
	func() float64 { return float64(commanddom.PayloadsRefused()) },
)
