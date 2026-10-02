package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scoping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopingHandler serves the Scoping overview.
type ScopingHandler struct {
	summary scoping.SummaryReader
	logger  *logger.Logger
}

// NewScopingHandler creates the handler.
func NewScopingHandler(summary scoping.SummaryReader, log *logger.Logger) *ScopingHandler {
	return &ScopingHandler{summary: summary, logger: log}
}

// GetSummary returns the Scoping overview counts in one call.
// @Summary      Scoping overview
// @Description  Tenant-wide readiness counts for CTEM scoping: the cycle in focus and its charter, crown jewels and their owners, business services and units, the boundary, attacker profiles, threat models and cycles.
// @Tags         Scoping
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  scoping.Summary
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /scoping/summary [get]
func (h *ScopingHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	s, err := h.summary.GetSummary(r.Context(), tid)
	if err != nil {
		h.logger.Error("scoping summary", "error", err)
		apierror.InternalServerError("failed to get scoping summary").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, s)
}
