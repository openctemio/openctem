package handler

// Asset freshness (docs/architecture/asset-freshness.md).

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
)

// AssetFreshnessResponse is an asset's freshness.
type AssetFreshnessResponse = assetfreshness.AssetView

// GetFreshness handles GET /api/v1/assets/{id}/freshness
// @Summary      Asset data freshness
// @Description  When each enrichable attribute class of the asset (DNS, registration, network owner, HTTP, TLS, ports) was last observed and by which tool, its freshness TTL, and its state: live (within the TTL), stale (past it), dead (past three TTLs) or never (a passive class that applies and nobody observed). The asset's state is its worst class.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  AssetFreshnessResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/freshness [get]
func (h *AssetHandler) GetFreshness(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	v, err := h.service.GetFreshness(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
