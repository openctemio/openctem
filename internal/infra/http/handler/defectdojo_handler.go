package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	ddapp "github.com/openctemio/api/internal/app/defectdojo"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// DefectDojoHandler exposes the DefectDojo co-existence sync (RFC-013): pull the
// tenant's DefectDojo findings and ingest them as CTIS. One-way, tenant-scoped.
type DefectDojoHandler struct {
	sync   *ddapp.SyncService
	logger *logger.Logger
}

// NewDefectDojoHandler creates the handler.
func NewDefectDojoHandler(sync *ddapp.SyncService, log *logger.Logger) *DefectDojoHandler {
	return &DefectDojoHandler{sync: sync, logger: log}
}

// Sync handles POST /api/v1/integrations/defectdojo/sync. The tenant is taken
// from the JWT (authoritative) — never from the request or the DefectDojo data.
func (h *DefectDojoHandler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}

	result, err := h.sync.SyncTenant(r.Context(), tid)
	if err != nil {
		if errors.Is(err, ddapp.ErrNoDefectDojoIntegration) {
			apierror.NotFound("no connected DefectDojo integration").WriteJSON(w)
			return
		}
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("defectdojo sync failed", "tenant_id", tenantID, "error", err)
		apierror.InternalServerError("DefectDojo sync failed").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
