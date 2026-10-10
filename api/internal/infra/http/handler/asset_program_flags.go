package handler

// Program asset flags on asset responses (RFC-065 §16.5): the system tags
// derived from program links and whether the asset is program-only. Read
// in one query per response; a failure leaves them out (the asset is still
// served) and is logged.

import (
	"context"
	"net/http"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
)

// ProgramAssetFlags are one asset's derived program fields.
type ProgramAssetFlags = bp.AssetFlags

// ProgramAssetFlagReader reads them for a page of assets of one tenant
// (*postgres.BountyProgramRepository).
type ProgramAssetFlagReader interface {
	ProgramAssetFlags(ctx context.Context, tenantID string, assetIDs []string) (map[string]ProgramAssetFlags, error)
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
	flags, err := h.programFlags.ProgramAssetFlags(r.Context(), tenantID, ids)
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
