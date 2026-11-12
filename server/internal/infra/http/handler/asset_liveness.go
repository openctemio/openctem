package handler

// Asset liveness on asset responses (docs/architecture/asset-liveness.md):
// alive, unreachable, unresolvable or gone, since when, and which of the
// organization's scan zones or sensors checked last. Read in one
// tenant-scoped query per response, for assets the caller already passed
// the data scope for; a failure leaves the field out (the asset is still
// served) and is logged.

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/liveness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetLivenessReader reads the liveness of a page of one tenant's assets
// (*postgres.AssetLivenessRepository).
type AssetLivenessReader interface {
	ForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]liveness.View, error)
}

// SetLiveness wires the asset liveness reader.
func (h *AssetHandler) SetLiveness(r AssetLivenessReader) { h.liveness = r }

func (h *AssetHandler) addLiveness(r *http.Request, tenantID string, out []*AssetResponse) {
	if h.liveness == nil || len(out) == 0 {
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
	views, err := h.liveness.ForAssets(r.Context(), tid, ids)
	if err != nil {
		h.logger.Warn("asset liveness not read", "error", err)
		return
	}
	for _, a := range out {
		id, err := shared.IDFromString(a.ID)
		if err != nil {
			continue
		}
		if v, ok := views[id]; ok {
			view := v
			a.Liveness = &view
		}
	}
}
