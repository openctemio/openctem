package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// RegistryTargetPairResponse is one built-in pair: a tool that accepts
// TargetType can scan assets of AssetType (an alias type is stored as its
// core type with SubType).
type RegistryTargetPairResponse struct {
	TargetType string `json:"target_type"`
	AssetType  string `json:"asset_type"`
	SubType    string `json:"sub_type,omitempty"`
}

// RegistryTargetPairsResponse lists the pairs the asset type registry
// declares scannable. They are read-only: they change with a release, and a
// mapping under /admin/target-mappings can only add to them.
type RegistryTargetPairsResponse struct {
	Data []RegistryTargetPairResponse `json:"data"`
}

// mappingCoveredByRegistryMessage is the 409 message of a mapping the
// registry already declares.
const mappingCoveredByRegistryMessage = "already covered by the asset type registry; mappings only add pairs the registry does not have"

// Registry lists the built-in target-type to asset-type pairs.
// @Summary List built-in target mappings (platform admin)
// @Description The pairs the asset type registry (scannable_by) already declares: which asset types a tool accepting a target type can scan. Read-only; custom mappings only add to them. Any admin role.
// @Tags Admin Target Mappings
// @Produce json
// @Success 200 {object} RegistryTargetPairsResponse
// @Security BearerAuth
// @Router /admin/target-mappings/registry [get]
func (h *AdminTargetMappingHandler) Registry(w http.ResponseWriter, _ *http.Request) {
	pairs := asset.ScanTargetPairs()
	resp := RegistryTargetPairsResponse{Data: make([]RegistryTargetPairResponse, 0, len(pairs))}
	for _, p := range pairs {
		if !tool.IsValidTargetType(p.TargetType) {
			continue
		}
		resp.Data = append(resp.Data, RegistryTargetPairResponse{TargetType: p.TargetType, AssetType: string(p.Type), SubType: p.SubType})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
