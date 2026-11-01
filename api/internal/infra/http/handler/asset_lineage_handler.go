package handler

// Discovery lineage (docs/architecture/easm.md, Discovery lineage).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
)

// AssetLineageNode is one asset of a discovery chain. A node outside the
// caller's data scope has hidden set and no id, name, type or discovery
// fields.
type AssetLineageNode struct {
	// Depth 0 is the asset itself, 1 its parent, and so on.
	Depth  int  `json:"depth"`
	Hidden bool `json:"hidden"`
	// Via is how this node leads to the node one depth below it: parent
	// (the asset's parent), contains, exposes, serves_certificate or
	// resolves_to. Empty for depth 0.
	Via             string     `json:"via,omitempty"`
	ID              string     `json:"id,omitempty"`
	Name            string     `json:"name,omitempty"`
	Type            string     `json:"type,omitempty"`
	DiscoverySource string     `json:"discovery_source,omitempty"`
	DiscoveryTool   string     `json:"discovery_tool,omitempty"`
	DiscoveredAt    *time.Time `json:"discovered_at,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
}

// AssetLineageResponse is how an asset was found, the asset first.
type AssetLineageResponse struct {
	Nodes []AssetLineageNode `json:"nodes"`
	// MaxDepth is how many ancestors the chain walks at most.
	MaxDepth int `json:"max_depth"`
	// Truncated is set when the chain goes on above the last node.
	Truncated bool `json:"truncated"`
}

// GetLineage handles GET /api/v1/assets/{id}/lineage
// @Summary      Asset discovery lineage
// @Description  How the asset was found: the asset (depth 0) and its ancestors up to the root, one parent per hop (the asset's parent, else the source of a contains, exposes, serves_certificate or resolves_to edge pointing at it), at most 5 ancestors, never revisiting an asset. Each node carries its discovery source, tool, discovery time and first-seen time. An ancestor outside the caller's data scope is returned with hidden set and no identifying field.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  AssetLineageResponse
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/lineage [get]
func (h *AssetHandler) GetLineage(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	l, err := h.service.GetLineage(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := AssetLineageResponse{Nodes: make([]AssetLineageNode, 0, len(l.Nodes)),
		MaxDepth: assetdom.LineageMaxDepth, Truncated: l.Truncated}
	for _, n := range l.Nodes {
		node := AssetLineageNode{Depth: n.Depth, Hidden: n.Hidden, Via: n.Via}
		if !n.Hidden {
			node.ID, node.Name, node.Type = n.ID.String(), n.Name, string(n.Type)
			node.DiscoverySource, node.DiscoveryTool = n.DiscoverySource, n.DiscoveryTool
			node.DiscoveredAt, node.FirstSeen = n.DiscoveredAt, n.FirstSeen
		}
		out.Nodes = append(out.Nodes, node)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
