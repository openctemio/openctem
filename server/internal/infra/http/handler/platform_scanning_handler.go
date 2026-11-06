package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PlatformScanningHandler serves platform scanning as one organization sees
// it: a managed service (regions, state, tools, the organization's own
// jobs), never the platform sensors behind it.
type PlatformScanningHandler struct {
	service *sensor.PlatformScanningService
	logger  *logger.Logger
}

// NewPlatformScanningHandler creates a PlatformScanningHandler.
func NewPlatformScanningHandler(service *sensor.PlatformScanningService, log *logger.Logger) *PlatformScanningHandler {
	return &PlatformScanningHandler{service: service, logger: log.With("handler", "platform_scanning")}
}

// Get godoc
// @Summary      Platform scanning
// @Description  Whether the organization can send scans to the platform's shared scanning, its regions and their state (available, busy, unavailable), the tools it runs, and the organization's own queued and running platform jobs. Nothing identifies a platform sensor and no other organization's load is shown. offered=false says nothing else.
// @Tags         Platform
// @Produce      json
// @Success      200  {object}  sensor.PlatformScanning
// @Security     BearerAuth
// @Router       /platform/scanning [get]
func (h *PlatformScanningHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}
	out, err := h.service.Get(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to read platform scanning", "error", err, "tenant_id", tenantID.String())
		apierror.InternalServerError("failed to read platform scanning").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
