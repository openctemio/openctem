package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// TargetMappingTypesResponse lists the values a target mapping may use.
type TargetMappingTypesResponse struct {
	// TargetTypes are the scanner target types (tool supported_targets values).
	TargetTypes []string `json:"target_types"`
	// AssetTypes are the asset types a target type can map to.
	AssetTypes []string `json:"asset_types"`
}

// Types lists the target types and asset types that a target mapping
// accepts, in the order the API defines them. These are exactly the values
// Create validates against, so clients do not keep their own copy.
// @Summary List accepted target-mapping types (platform admin)
// @Description The target types and asset types that POST /admin/target-mappings accepts. Any admin role.
// @Tags Admin Target Mappings
// @Produce json
// @Success 200 {object} TargetMappingTypesResponse
// @Security BearerAuth
// @Router /admin/target-mappings/types [get]
func (h *AdminTargetMappingHandler) Types(w http.ResponseWriter, _ *http.Request) {
	assetTypes := asset.AllAssetTypes()
	resp := TargetMappingTypesResponse{
		TargetTypes: append([]string{}, tool.ValidTargetTypes...),
		AssetTypes:  make([]string, 0, len(assetTypes)),
	}
	for _, t := range assetTypes {
		resp.AssetTypes = append(resp.AssetTypes, string(t))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
