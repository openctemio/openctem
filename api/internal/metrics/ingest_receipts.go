package metrics

// Ingest receipts (docs/rfcs/RFC-122-ingest-receipts.md). No tenant label.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// IngestReceiptWriteFailures counts receipt deltas that could not be
// written, by origin (ingest, coverage, upload). The findings themselves
// are stored; the receipt under-reports them.
var IngestReceiptWriteFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "openctem_ingest_receipt_write_failures_total",
		Help: "Receipt deltas that could not be written, by origin (ingest, coverage, upload)",
	},
	[]string{"origin"},
)
