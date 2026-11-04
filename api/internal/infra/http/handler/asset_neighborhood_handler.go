package handler

// Asset neighborhood (docs/architecture/asset-relationships.md,
// "Neighborhood").

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
)

// neighborhoodLimitParam is the query parameter of the node cap.
const neighborhoodLimitParam = "limit"

// NeighborhoodNodeResponse is an asset of a neighborhood the caller may see.
type NeighborhoodNodeResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	SubType     string `json:"sub_type,omitempty"`
	Status      string `json:"status,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	Exposure    string `json:"exposure,omitempty"`
	// Distance is the number of hops from the asset (0 for the asset);
	// absent for a lineage ancestor beyond the requested depth.
	Distance *int `json:"distance,omitempty"`
	// Expanded is set when this asset's own relationships were read: its
	// neighbors, clusters and hidden count are in the answer.
	Expanded bool `json:"expanded"`
	// HiddenNeighbors counts the related assets outside the caller's data
	// scope (expanded nodes only).
	HiddenNeighbors int `json:"hidden_neighbors"`
}

// NeighborhoodEdgeResponse is one relationship, source to target as stored.
type NeighborhoodEdgeResponse struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

// NeighborhoodClusterResponse is a group of related assets returned as a
// count: the anchor's relationships of one type in one direction. Expand it
// with GET /assets/{anchor}/relationships/groups?type=&direction=.
type NeighborhoodClusterResponse struct {
	// ID is stable for the same anchor, type and direction.
	ID     string `json:"id"`
	Anchor string `json:"anchor"`
	Type   string `json:"type"`
	// Direction is outgoing when the anchor is the source.
	Direction string `json:"direction"`
	Count     int    `json:"count"`
	// ByType is the count per asset type.
	ByType map[string]int `json:"by_type"`
}

// AssetNeighborhoodResponse is the neighborhood of one asset.
type AssetNeighborhoodResponse struct {
	AssetID   string                        `json:"asset_id"`
	Depth     int                           `json:"depth"`
	Direction string                        `json:"direction"`
	MaxNodes  int                           `json:"max_nodes"`
	Nodes     []NeighborhoodNodeResponse    `json:"nodes"`
	Edges     []NeighborhoodEdgeResponse    `json:"edges"`
	Clusters  []NeighborhoodClusterResponse `json:"clusters"`
	// Lineage is the asset's discovery chain up to its root (same shape as
	// GET /assets/{id}/lineage); its visible nodes are also in nodes.
	Lineage AssetLineageResponse `json:"lineage"`
	// Truncated is set when the node cap stopped the walk; the rest is
	// counted in clusters.
	Truncated bool `json:"truncated"`
	// HiddenCount sums hidden_neighbors.
	HiddenCount int `json:"hidden_count"`
}

// Neighborhood handles GET /api/v1/assets/{id}/neighborhood.
//
// @Summary      Asset neighborhood
// @Description  The assets around an asset up to depth hops away (1 to 3, default 2) in both directions (or only out/in), with the asset's discovery lineage up to its root. A group of more than 8 related assets of one relationship type and direction on one asset comes back as a cluster with its count by asset type (expand it with the relationship groups endpoint). At most limit assets (default 150, max 300); the rest is counted in clusters and truncated is set. Related assets outside the caller's data scope are never returned or walked through: they are counted per node (hidden_neighbors). Filters: types (asset types) and relations (relationship types), comma separated.
// @Tags         Asset Relationships
// @Produce      json
// @Security     BearerAuth
// @Param        id         path   string  true   "Asset ID"
// @Param        depth      query  int     false  "Hops from the asset, 1 to 3 (default 2)"
// @Param        direction  query  string  false  "both (default), out or in"
// @Param        types      query  string  false  "Only these asset types, comma separated"
// @Param        relations  query  string  false  "Only these relationship types, comma separated"
// @Param        limit      query  int     false  "Most assets returned (default 150, max 300)"
// @Success      200  {object}  AssetNeighborhoodResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /assets/{id}/neighborhood [get]
func (h *AssetRelationshipHandler) Neighborhood(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()
	in := assetapp.NeighborhoodInput{
		Direction: query.Get("direction"),
		Types:     splitList(query.Get("types")),
		Relations: splitList(query.Get("relations")),
	}
	for _, p := range []struct {
		name string
		dst  *int
	}{{"depth", &in.Depth}, {neighborhoodLimitParam, &in.MaxNodes}} {
		if v := query.Get(p.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				apierror.BadRequest(p.name + " must be a positive integer").WriteJSON(w)
				return
			}
			*p.dst = n
		}
	}

	res, err := h.service.Neighborhood(r.Context(), tenantID, chi.URLParam(r, "id"), in)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toNeighborhoodResponse(chi.URLParam(r, "id"), res))
}

func toNeighborhoodResponse(assetID string, n *assetdom.Neighborhood) AssetNeighborhoodResponse {
	out := AssetNeighborhoodResponse{
		AssetID: assetID, Depth: n.Query.Depth, Direction: n.Query.Direction, MaxNodes: n.Query.MaxNodes,
		Nodes:    make([]NeighborhoodNodeResponse, 0, len(n.Nodes)),
		Edges:    make([]NeighborhoodEdgeResponse, 0, len(n.Edges)),
		Clusters: make([]NeighborhoodClusterResponse, 0, len(n.Clusters)),
		Lineage:  toLineageResponse(&n.Lineage), Truncated: n.Truncated, HiddenCount: n.HiddenCount,
	}
	for _, x := range n.Nodes {
		node := NeighborhoodNodeResponse{
			ID: x.ID.String(), Name: x.Name, Type: string(x.Type), SubType: x.SubType, Status: x.Status,
			Criticality: x.Criticality, Exposure: x.Exposure, Expanded: x.Expanded, HiddenNeighbors: x.HiddenNeighbors,
		}
		if x.Distance >= 0 {
			d := x.Distance
			node.Distance = &d
		}
		out.Nodes = append(out.Nodes, node)
	}
	for _, e := range n.Edges {
		out.Edges = append(out.Edges, NeighborhoodEdgeResponse{Source: e.Source.String(), Target: e.Target.String(), Type: string(e.Type)})
	}
	for _, c := range n.Clusters {
		by := make(map[string]int, len(c.ByType))
		for t, v := range c.ByType {
			by[string(t)] = v
		}
		out.Clusters = append(out.Clusters, NeighborhoodClusterResponse{
			ID:     "cluster:" + c.Anchor.String() + ":" + string(c.Type) + ":" + c.Direction,
			Anchor: c.Anchor.String(), Type: string(c.Type), Direction: c.Direction, Count: c.Count(), ByType: by,
		})
	}
	sort.SliceStable(out.Clusters, func(i, j int) bool { return out.Clusters[i].Count > out.Clusters[j].Count })
	return out
}
