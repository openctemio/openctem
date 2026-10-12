package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StateChangeCountsResponse holds the total of each "What changed" view for
// one window: the same numbers as `total` of the five list endpoints.
type StateChangeCountsResponse struct {
	Appeared        int64 `json:"appeared"`
	Disappeared     int64 `json:"disappeared"`
	NewlyExposed    int64 `json:"newly_exposed"`
	ExposureChanges int64 `json:"exposure_changes"`
	ShadowIT        int64 `json:"shadow_it"`
}

// changeViewPresets are the five views, with the preset each list endpoint
// applies (appearances, disappearances, newly-exposed, exposure-changes,
// shadow-it).
func changeViewPresets() map[string]listPreset {
	shadow := asset.ScopeShadow
	return map[string]listPreset{
		"appeared":    {types: []asset.StateChangeType{asset.StateChangeAppeared}, forced: true},
		"disappeared": {types: []asset.StateChangeType{asset.StateChangeDisappeared}, forced: true},
		"newly_exposed": {
			types: []asset.StateChangeType{
				asset.StateChangeExposureChanged, asset.StateChangeInternetExposureChanged,
			},
			newValues: []string{string(asset.ExposurePublic), "true"},
			forced:    true,
		},
		"exposure_changes": {types: []asset.StateChangeType{
			asset.StateChangeExposureChanged, asset.StateChangeInternetExposureChanged,
		}, forced: true},
		"shadow_it": {
			types:      []asset.StateChangeType{asset.StateChangeAppeared},
			assetScope: &shadow,
			forced:     true,
		},
	}
}

// Counts handles GET /api/v1/state-history/counts
// @Summary      Count every "What changed" view
// @Description  The total of each change view (appearances, disappearances, newly exposed, exposure changes,
// @Description  shadow IT) for one window, in one response: the same numbers as `total` of the five list
// @Description  endpoints, with the caller's data scope. internet_facing narrows every view but newly
// @Description  exposed, which is internet-facing by definition.
// @Tags         Asset State History
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Success      200  {object}  StateChangeCountsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/counts [get]
func (h *AssetStateHistoryHandler) Counts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	base, _, ok := h.parseListOptions(w, r)
	if !ok {
		return
	}
	if base.From == nil {
		since := h.parseSince(r)
		base.From = &since
	}
	base.ChangeType, base.ChangeTypes = nil, nil
	base.Limit, base.Offset = 1, 0
	base.Scope, err = resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	totals := make(map[string]int64, 5)
	for view, preset := range changeViewPresets() {
		opts := base
		opts.ChangeTypes = preset.types
		opts.NewValues = preset.newValues
		opts.AssetScope = preset.assetScope
		if view == "newly_exposed" {
			opts.AssetInternetFacing = nil
		}
		_, total, err := h.repo.List(ctx, tenantID, opts)
		if err != nil {
			h.logger.Error("failed to count state history", "view", view, "error", err)
			apierror.InternalError(err).WriteJSON(w)
			return
		}
		totals[view] = int64(total)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(StateChangeCountsResponse{
		Appeared:        totals["appeared"],
		Disappeared:     totals["disappeared"],
		NewlyExposed:    totals["newly_exposed"],
		ExposureChanges: totals["exposure_changes"],
		ShadowIT:        totals["shadow_it"],
	})
}
