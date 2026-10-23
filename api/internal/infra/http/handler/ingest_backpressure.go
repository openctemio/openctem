package handler

// Back-pressure answers of the upload endpoints
// (docs/rfcs/RFC-122-ingest-receipts.md, "Fairness and limits").

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// writeBackpressure answers an upload refused by the queue: 429 with
// Retry-After when the organization's queue is full, 503 when its depth
// could not be read (nothing was stored). It reports whether err was one.
func writeBackpressure(w http.ResponseWriter, err error) bool {
	var full *ingestqueue.ErrQueueFull
	switch {
	case errors.As(err, &full):
		secs := int(math.Ceil(full.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		apierror.New(http.StatusTooManyRequests, "INGEST_QUEUE_FULL",
			"The organization's ingest queue is full; nothing was stored. Retry after the advised delay.").WriteJSON(w)
		return true
	case errors.Is(err, ingestqueue.ErrDepthUnknown):
		w.Header().Set("Retry-After", "30")
		apierror.New(http.StatusServiceUnavailable, "INGEST_QUEUE_UNAVAILABLE",
			"The ingest queue could not be checked; nothing was stored. Retry later.").WriteJSON(w)
		return true
	}
	return false
}
