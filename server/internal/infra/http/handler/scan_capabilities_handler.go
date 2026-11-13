package handler

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// scanCapabilityReader answers what the organization may scan
// (*scansvc.Service).
type scanCapabilityReader interface {
	ActiveScanningAllowed(ctx context.Context, tenantID shared.ID) (bool, error)
}

// ScanCapabilitiesResponse is what the caller's organization may scan, for
// the scan wizard to offer only what will be accepted.
type ScanCapabilitiesResponse struct {
	// ActiveScanning: scans above passive (active or intrusive intensity,
	// active tools) are allowed. False for a passive-only organization.
	ActiveScanning bool `json:"active_scanning"`
}

func (h *ScanHandler) capabilityReader() scanCapabilityReader {
	if h.capabilities != nil {
		return h.capabilities
	}
	if h.service != nil {
		return h.service
	}
	return nil
}

// GetCapabilities handles GET /api/v1/scans/capabilities
// @Summary      What this organization may scan
// @Description  Whether the caller's organization may run scans above passive
// @Description  (the active_scanning entitlement). The organization comes from
// @Description  the credential. Advice for the console only: create, change
// @Description  and run still refuse a scan above passive for a passive-only
// @Description  organization.
// @Tags         Scans
// @Produce      json
// @Success      200  {object}  ScanCapabilitiesResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/capabilities [get]
func (h *ScanHandler) GetCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return
	}
	reader := h.capabilityReader()
	if reader == nil {
		apierror.InternalServerError("scan capabilities are not available").WriteJSON(w)
		return
	}
	active, err := reader.ActiveScanningAllowed(r.Context(), tenantID)
	if err != nil {
		h.logger.Warn("read scan capabilities", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		apierror.InternalServerError("scan capabilities could not be read").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ScanCapabilitiesResponse{ActiveScanning: active})
}
