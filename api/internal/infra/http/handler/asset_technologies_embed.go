package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Technologies embedded in asset responses (docs/rfcs/RFC-112-asset-technologies.md):
// a list shows a few chips per row, a single asset all of them.
const (
	listTechnologiesPerAsset = 20
	getTechnologiesPerAsset  = assettech.MaxListed
)

// AssetTechnologyBrief is one technology detected on an asset, as asset
// responses embed it. GET /assets/{id}/technologies has every field.
type AssetTechnologyBrief struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category"`
}

// SetTechnologyReader wires the technologies embedded in asset responses.
func (h *AssetHandler) SetTechnologyReader(r assettech.Repository) {
	h.technologies = r
}

// addTechnologies fills the technologies of the responses, in one query.
// The responses are assets the caller may already read. A failure leaves
// them out and is logged.
func (h *AssetHandler) addTechnologies(r *http.Request, tenantID string, perAsset int, out []*AssetResponse) {
	if h.technologies == nil || len(out) == 0 {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	ids := make([]shared.ID, 0, len(out))
	for _, a := range out {
		if id, err := shared.IDFromString(a.ID); err == nil {
			ids = append(ids, id)
		}
	}
	byAsset, err := h.technologies.ListByAssets(r.Context(), tid, ids, perAsset)
	if err != nil {
		h.logger.Error("asset technologies", "error", err)
		return
	}
	for _, a := range out {
		id, err := shared.IDFromString(a.ID)
		if err != nil {
			continue
		}
		for _, t := range byAsset[id] {
			a.Technologies = append(a.Technologies, AssetTechnologyBrief{Name: t.Name, Version: t.Version, Category: string(t.Category)})
		}
	}
}
