package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// clientErrorMaxBody bounds a client error report. The report is one short
// field; anything longer is not a report.
const clientErrorMaxBody = 1024

// clientErrorKind maps a reported kind to one of the fixed kinds; anything
// else is "other". It returns a constant, never the caller's string, so the
// label set is fixed and nothing the caller sent reaches the log.
func clientErrorKind(reported string) string {
	switch reported {
	case "chunk_load":
		return "chunk_load"
	case "render":
		return "render"
	case "unhandled":
		return "unhandled"
	default:
		return "other"
	}
}

// ClientErrorReport is what the web console sends when it hits an error.
// Only the kind is accepted: no message, stack, URL or user detail, so a
// report can carry no personal or tenant data to the operator's alerts.
type ClientErrorReport struct {
	// Kind: chunk_load (a code chunk failed to load, typical after a
	// deploy), render (an error boundary caught a render error),
	// unhandled (an uncaught error or rejection), other.
	Kind string `json:"kind" example:"chunk_load" enums:"chunk_load,render,unhandled,other"`
}

// ClientErrorHandler counts errors browsers report, for the operator's
// web error alert (docs/operations/monitoring.md, WebClientErrors).
type ClientErrorHandler struct {
	logger *logger.Logger
}

// NewClientErrorHandler creates the handler.
func NewClientErrorHandler(log *logger.Logger) *ClientErrorHandler {
	return &ClientErrorHandler{logger: log}
}

// Report counts one client error.
// @Summary      Report a web client error
// @Description  Counts an error the web console hit, by kind, for operator alerting. Public (errors happen before sign-in too), rate limited per client address and overall. Only the kind is kept.
// @Tags         Health
// @Accept       json
// @Param        body  body  ClientErrorReport  true  "The error kind"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /client-errors [post]
func (h *ClientErrorHandler) Report(w http.ResponseWriter, r *http.Request) {
	var req ClientErrorReport
	if err := json.NewDecoder(io.LimitReader(r.Body, clientErrorMaxBody)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid report").WriteJSON(w)
		return
	}
	kind := clientErrorKind(req.Kind)
	metrics.WebClientErrorsTotal.WithLabelValues(kind).Inc()
	h.logger.Warn("web client error reported", "kind", kind)
	w.WriteHeader(http.StatusNoContent)
}
