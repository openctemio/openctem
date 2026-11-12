package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetTechnologyHandler serves GET /api/v1/assets/{id}/technologies
// (docs/rfcs/RFC-112-asset-technologies.md): what probes detected on the
// asset, by category.
type AssetTechnologyHandler struct {
	repo      assettech.Repository
	assets    asset.Repository
	dataScope DataScopeEnforcer
	logger    *logger.Logger
}

// NewAssetTechnologyHandler creates the handler.
func NewAssetTechnologyHandler(repo assettech.Repository, assets asset.Repository, log *logger.Logger) *AssetTechnologyHandler {
	return &AssetTechnologyHandler{repo: repo, assets: assets, logger: log}
}

// SetDataScope wires the Layer 2 data scope. Returns h for chaining.
func (h *AssetTechnologyHandler) SetDataScope(e DataScopeEnforcer) *AssetTechnologyHandler {
	h.dataScope = e
	return h
}

// AssetTechnologyResponse is one technology detected on an asset.
type AssetTechnologyResponse struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category"`
	// Kind: software, infrastructure, http_security or marketing.
	Kind string `json:"kind"`
	// Confidence is the tool's own, 0-100; 0 = the tool gave none.
	Confidence int       `json:"confidence"`
	Source     string    `json:"source,omitempty"`
	FirstSeen  time.Time `json:"first_seen_at"`
	LastSeen   time.Time `json:"last_seen_at"`
}

// AssetTechnologyListResponse is the list.
type AssetTechnologyListResponse struct {
	Data []AssetTechnologyResponse `json:"data"`
}

// List handles GET /api/v1/assets/{id}/technologies.
// @Summary      List the technologies detected on an asset
// @Description  Every technology a fingerprinting probe detected on the asset (web server, framework or CMS, language, JavaScript library, CDN, hosting, WAF or security service, analytics, security header, other), with its version when known, the tool's confidence and when it was first and last seen. Only products with a version or CPE also appear as software. An asset outside the caller's data scope answers 404.
// @Tags         Assets
// @Produce      json
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetTechnologyListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /assets/{id}/technologies [get]
func (h *AssetTechnologyHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.GetTenantID(ctx))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	assetID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	// The asset must be the tenant's and in the caller's data scope; both
	// misses answer the same 404.
	if _, err := h.assets.GetByID(ctx, tenantID, assetID); err != nil || !assetInDataScope(ctx, h.dataScope, tenantID, assetID) {
		apierror.NotFound("Asset").WriteJSON(w)
		return
	}
	techs, err := h.repo.ListByAsset(ctx, tenantID, assetID)
	if err != nil {
		h.logger.Error("asset technologies", "error", err)
		apierror.InternalServerError("Failed to list technologies").WriteJSON(w)
		return
	}
	out := AssetTechnologyListResponse{Data: make([]AssetTechnologyResponse, 0, len(techs))}
	for _, t := range techs {
		out.Data = append(out.Data, AssetTechnologyResponse{
			Name: t.Name, Version: t.Version, Category: string(t.Category), Kind: string(t.Category.Kind()),
			Confidence: t.Confidence, Source: t.Source, FirstSeen: t.FirstSeen, LastSeen: t.LastSeen,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
