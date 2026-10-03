package handler

import (
	"context"
	"encoding/json"
	"net/http"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMSummarizer builds the EASM overview.
type EASMSummarizer interface {
	Summary(ctx context.Context, tenantID shared.ID) (*easmapp.Summary, error)
}

// EASMHandler serves the EASM overview (RFC-036 §6.10).
type EASMHandler struct {
	svc    EASMSummarizer
	logger *logger.Logger
}

// NewEASMHandler creates the handler.
func NewEASMHandler(svc EASMSummarizer, log *logger.Logger) *EASMHandler {
	return &EASMHandler{svc: svc, logger: log}
}

// Summary handles GET /api/v1/easm/summary
// @Summary      EASM overview
// @Description  The external attack surface in one call: surface assets by type and internet-facing services, attribution (confirmed, awaiting review and the age of the oldest review item, dependency, monitor only, rejected), assets first seen in the last 7/30 days and since the latest CTEM cycle started, open external exposures by severity and type, the top open risks, and how fresh the Certificate-Transparency monitoring is. Narrowed to the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  easmapp.Summary
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/summary [get]
func (h *EASMHandler) Summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	out, err := h.svc.Summary(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to build EASM summary", "error", err)
		apierror.InternalServerError("failed to build EASM summary").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
