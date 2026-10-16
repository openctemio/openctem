package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
)

// AssetTechnologyFacetResponse is one technology across the assets the
// caller may list.
type AssetTechnologyFacetResponse struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	Category   string `json:"category"`
	AssetCount int    `json:"asset_count"`
}

// AssetTechnologyFacetsResponse is the list.
type AssetTechnologyFacetsResponse struct {
	Data []AssetTechnologyFacetResponse `json:"data"`
}

// ListTechnologyFacets handles GET /api/v1/assets/technologies.
// @Summary      Technologies on the organization's assets
// @Description  The technologies detected on the assets the caller may list (the same data scope as the asset list), most used first, with their category and asset count: the options of the asset list's technology filter (RFC-112).
// @Tags         Assets
// @Produce      json
// @Param        q         query  string  false  "Name contains (case-insensitive, at most 128 characters)"
// @Param        category  query  string  false  "web_server, framework, language, js_library, cdn, hosting, waf, analytics, security_header or other"
// @Param        limit     query  int     false  "At most this many (1-100, default 100)"
// @Success      200  {object}  AssetTechnologyFacetsResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /assets/technologies [get]
func (h *AssetHandler) ListTechnologyFacets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()
	limit := assettech.MaxFacets
	if v := query.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > assettech.MaxFacets {
			apierror.BadRequest("limit must be between 1 and 100").WriteJSON(w)
			return
		}
		limit = n
	}
	facets, err := h.service.TechnologyFacets(r.Context(), tenantID,
		middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()),
		query.Get("q"), query.Get("category"), limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := AssetTechnologyFacetsResponse{Data: make([]AssetTechnologyFacetResponse, 0, len(facets))}
	for _, f := range facets {
		out.Data = append(out.Data, AssetTechnologyFacetResponse{
			Name: f.Name, Key: f.Key, Category: string(f.Category), AssetCount: f.AssetCount,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
