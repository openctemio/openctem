package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetIdentifierLister lists the identifiers recorded for assets.
type AssetIdentifierLister interface {
	ListByAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]asset.Identifier, error)
}

// AssetIdentifierHandler serves the identifiers an asset was seen with.
type AssetIdentifierHandler struct {
	identifiers AssetIdentifierLister
	assets      asset.Repository
	logger      *logger.Logger
}

// NewAssetIdentifierHandler creates the handler.
func NewAssetIdentifierHandler(identifiers AssetIdentifierLister, assets asset.Repository, log *logger.Logger) *AssetIdentifierHandler {
	return &AssetIdentifierHandler{identifiers: identifiers, assets: assets, logger: log}
}

// AssetIdentifierResponse is one identifier of an asset.
type AssetIdentifierResponse struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Strong    bool      `json:"strong"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// List handles GET /api/v1/assets/{id}/identifiers
// @Summary      List asset identifiers
// @Description  Identifiers the asset was seen with (host ID, cloud ID, BIOS UUID, serial, MAC, SCM repository ID, FQDN, hostname, IP), strongest first. Ingest matches incoming assets on these.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID"
// @Success      200  {object}  object{data=[]AssetIdentifierResponse,total=int}
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/identifiers [get]
func (h *AssetIdentifierHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	assetID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	// Tenant-scoped existence check, same as the asset's other sub-resources.
	if _, err := h.assets.GetByID(ctx, tenantID, assetID); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to verify asset", "error", err)
		apierror.InternalServerError("failed to load asset").WriteJSON(w)
		return
	}

	ids, err := h.identifiers.ListByAssets(ctx, tenantID, []shared.ID{assetID})
	if err != nil {
		h.logger.Error("failed to list asset identifiers", "error", err)
		apierror.InternalServerError("failed to list identifiers").WriteJSON(w)
		return
	}
	sort.SliceStable(ids, func(i, j int) bool {
		if ids[i].Kind.Rank() != ids[j].Kind.Rank() {
			return ids[i].Kind.Rank() < ids[j].Kind.Rank()
		}
		return ids[i].LastSeen.After(ids[j].LastSeen)
	})
	out := make([]AssetIdentifierResponse, 0, len(ids))
	for _, id := range ids {
		out = append(out, AssetIdentifierResponse{
			Kind: string(id.Kind), Value: id.Value, Strong: id.Kind.IsStrong(), Source: id.Source,
			FirstSeen: id.FirstSeen, LastSeen: id.LastSeen,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out, "total": len(out)})
}
