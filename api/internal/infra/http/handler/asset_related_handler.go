package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// RelatedAssetRef is the asset at the other end of an edge.
type RelatedAssetRef struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	SubType     string     `json:"sub_type,omitempty"`
	Status      string     `json:"status,omitempty"`
	Criticality string     `json:"criticality,omitempty"`
	Exposure    string     `json:"exposure,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
}

// RelatedAssetItem is one edge seen from the asset being viewed.
type RelatedAssetItem struct {
	RelationshipID  string          `json:"relationship_id"`
	Type            string          `json:"type"`
	Direction       string          `json:"direction"`
	Asset           RelatedAssetRef `json:"asset"`
	DiscoveryMethod string          `json:"discovery_method"`
	Confidence      string          `json:"confidence"`
	IsControlPlane  bool            `json:"is_control_plane"`
	LastVerified    *time.Time      `json:"last_verified,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// RelatedAssetGroupResponse is every edge of one type in one direction.
type RelatedAssetGroupResponse struct {
	Type      string             `json:"type"`
	Direction string             `json:"direction"`
	Total     int64              `json:"total"`
	Items     []RelatedAssetItem `json:"items"`
}

// RelatedAssetsResponse is the grouped answer for one asset.
type RelatedAssetsResponse struct {
	Groups []RelatedAssetGroupResponse `json:"groups"`
	Total  int64                       `json:"total"`
	// HiddenCount counts related assets outside the caller's data scope.
	HiddenCount int64 `json:"hidden_count"`
}

// RelatedGroups handles GET /api/v1/assets/{id}/relationships/groups.
//
// @Summary      Related assets grouped by relationship
// @Description  The relationships of an asset grouped by type and direction, each group with its total and its first rows (most critical related asset first). With type and direction it pages through one group. Related assets outside the caller's data scope are only counted (hidden_count).
// @Tags         Asset Relationships
// @Produce      json
// @Security     BearerAuth
// @Param        id         path   string  true   "Asset ID"
// @Param        type       query  string  false  "Only this relationship type"
// @Param        direction  query  string  false  "outgoing or incoming"
// @Param        q          query  string  false  "Related asset name contains"
// @Param        offset     query  int     false  "Rows to skip in each group"
// @Param        limit      query  int     false  "Rows per group (default 5, max 100)"
// @Success      200  {object}  RelatedAssetsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/relationships/groups [get]
func (h *AssetRelationshipHandler) RelatedGroups(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	in := assetapp.RelatedAssetsInput{
		Type:      query.Get("type"),
		Direction: query.Get("direction"),
		Search:    query.Get("q"),
	}
	for _, p := range []struct {
		name string
		dst  *int
	}{{"offset", &in.Offset}, {"limit", &in.Limit}} {
		if v := query.Get(p.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				apierror.BadRequest(p.name + " must be a non-negative integer").WriteJSON(w)
				return
			}
			*p.dst = n
		}
	}

	res, err := h.service.RelatedAssets(r.Context(), tenantID, chi.URLParam(r, "id"), in)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	out := RelatedAssetsResponse{Groups: make([]RelatedAssetGroupResponse, 0, len(res.Groups)), Total: res.Total, HiddenCount: res.HiddenCount}
	for _, g := range res.Groups {
		items := make([]RelatedAssetItem, 0, len(g.Items))
		for _, it := range g.Items {
			items = append(items, toRelatedAssetItem(it))
		}
		out.Groups = append(out.Groups, RelatedAssetGroupResponse{Type: g.Type.String(), Direction: g.Direction, Total: g.Total, Items: items})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

func toRelatedAssetItem(it asset.RelatedAsset) RelatedAssetItem {
	return RelatedAssetItem{
		RelationshipID: it.RelationshipID.String(),
		Type:           it.Type.String(),
		Direction:      it.Direction,
		Asset: RelatedAssetRef{
			ID:          it.AssetID.String(),
			Name:        it.AssetName,
			Type:        it.AssetType.String(),
			SubType:     it.AssetSubType,
			Status:      it.AssetStatus,
			Criticality: it.Criticality,
			Exposure:    it.Exposure,
			LastSeen:    it.AssetLastSeen,
		},
		DiscoveryMethod: it.DiscoveryMethod,
		Confidence:      it.Confidence,
		IsControlPlane:  it.IsControlPlane,
		LastVerified:    it.LastVerified,
		CreatedAt:       it.CreatedAt,
	}
}
