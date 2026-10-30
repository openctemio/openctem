package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// assetViewTenantParts caps the parts one tenant's asset views run at the
// same time, across all its callers. Each part is a single-asset read.
const assetViewTenantParts = 8

// assetViewReadCost is what one asset view takes from the caller's per-user
// read budget: a few reads for the first screen of an asset, instead of one
// per panel.
const assetViewReadCost = 3

// AssetViewGate is the asset itself: it is read first, and unless it answers
// 200 the view holds only that part.
func AssetViewGate(id string) string { return "/api/v1/assets/" + id }

// AssetViewParts are the reads the asset page shows on load, by the exact URL
// the web asks for each one (research/335). The id has been parsed as a
// UUID, so a part URL never carries text from the request.
func AssetViewParts(id string) []string {
	a := "/api/v1/assets/" + id
	return []string{
		a + "/attribution",
		a + "/attribute-sources",
		a + "/freshness",
		a + "/coverage",
		a + "/identifiers",
		a + "/state-history?change_type=renamed&per_page=20",
		a + "/changes?limit=50",
		a + "/web-evidence",
		a + "/resolved-ports",
	}
}

// AssetViewHandler serves GET /assets/{id}/view: the asset and the reads its
// page shows on load, in one response. Every part is sent through the API's
// own router with the caller's credentials, so it passes exactly its
// endpoint's gates (permission, module, data scope); a part the caller may
// not read keeps its own status and error code and no data, and the page
// shows that panel as absent. Only AssetViewParts of the parsed id are
// dispatched; nothing else in the request chooses a path.
type AssetViewHandler struct {
	view *viewParts
}

// NewAssetViewHandler creates the handler. router returns the API's root
// router (read at request time). A nil log logs through the request's logger.
func NewAssetViewHandler(router func() http.Handler, log *logger.Logger) *AssetViewHandler {
	return &AssetViewHandler{view: newViewParts(router, log, viewOptions{
		name: "asset view", tenantParts: assetViewTenantParts, passErrors: true, readCost: assetViewReadCost,
	})}
}

// View handles GET /api/v1/assets/{id}/view
// @Summary      Asset page view
// @Description  The asset and the reads its page shows on load, in one response: each part keyed by the URL of its endpoint, with that endpoint's status and JSON body (on a 4xx, its error body). Every part goes through its own endpoint's permission, module and data-scope gates. The asset is read first; unless it answers 200 (missing, out of scope), the view holds only that part.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  ViewResponse
// @Failure      400  {object}  apierror.Error
// @Router       /assets/{id}/view [get]
func (h *AssetViewHandler) View(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	canonical := id.String()
	h.view.serve(w, r, AssetViewGate(canonical), AssetViewParts(canonical))
}
