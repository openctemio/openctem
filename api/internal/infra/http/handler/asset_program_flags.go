package handler

// Program asset flags on asset responses (RFC-065 §16.5): the system tags
// derived from program links and whether the asset is program-only. Read
// in one query per response; a failure leaves them out (the asset is still
// served) and is logged.

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramAssetFlags are one asset's derived program fields.
type ProgramAssetFlags = bp.AssetFlags

// ProgramAssetFlagReader reads them for a page of assets of one tenant
// (*postgres.BountyProgramRepository).
type ProgramAssetFlagReader interface {
	// ProgramAssetFlagsFor leaves out what tells a viewer of a private
	// program they are not a member of (RFC-065 §15.3).
	ProgramAssetFlagsFor(ctx context.Context, tenantID string, assetIDs []string, viewer shared.ProgramViewer) (map[string]ProgramAssetFlags, error)
}

// SetProgramFlags wires the program asset flags.
func (h *AssetHandler) SetProgramFlags(r ProgramAssetFlagReader) { h.programFlags = r }

func (h *AssetHandler) addProgramFlags(r *http.Request, tenantID string, out []*AssetResponse) {
	if h.programFlags == nil || len(out) == 0 {
		return
	}
	ids := make([]string, 0, len(out))
	for _, a := range out {
		ids = append(ids, a.ID)
	}
	uid, _ := shared.IDFromString(middleware.GetUserID(r.Context()))
	viewer := shared.ProgramViewer{UserID: uid, Owner: middleware.IsOwner(r.Context())}
	flags, err := h.programFlags.ProgramAssetFlagsFor(r.Context(), tenantID, ids, viewer)
	if err != nil {
		h.logger.Warn("program asset flags not read", "error", err)
		return
	}
	for _, a := range out {
		if f, ok := flags[a.ID]; ok {
			a.SystemTags, a.ProgramOnly = f.SystemTags, f.ProgramOnly
		}
	}
}
