package handler

// Asset coverage (docs/rfcs/RFC-093-asset-coverage.md).

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
)

// AssetCoverageResponse is an asset's coverage.
type AssetCoverageResponse = coverage.AssetView

// GetCoverage handles GET /api/v1/assets/{id}/coverage
// @Summary      Asset coverage
// @Description  For each capability the asset's type needs (registry coverage policy) and any other capability run on it: its state (due, queued, covered, failed, blocked, paused, not_applicable), the reason (a closed code), the last attempt and success, the outcome, the next due time, and whether it is a coverage gap (no success for more than twice its cadence). For a pair paused because its target did not answer, unreached_from names the organization's own scan zone or sensor that tried (never a platform sensor).
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  AssetCoverageResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/coverage [get]
func (h *AssetHandler) GetCoverage(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	v, err := h.service.GetCoverage(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
