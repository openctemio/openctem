package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/asset"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// newPasteAssets wires the creation of the missing assets of a pasted group
// list: the asset service creates them, the active gate says which names the
// organization's scope covers, and the scan stamper holds the others as
// candidates.
func newPasteAssets(assets *asset.AssetService, gate *easmapp.ActiveGate, holder ingest.ImportCandidateHolder) asset.PasteAssets {
	return asset.PasteAssets{
		Create: assets.CreateAsset,
		Covered: func(ctx context.Context, tenantID shared.ID, names []string) (map[string]bool, error) {
			via, err := gate.CoverOf(ctx, tenantID, names)
			if err != nil {
				return nil, err
			}
			out := make(map[string]bool, len(via))
			for n := range via {
				out[n] = true
			}
			return out, nil
		},
		HoldCandidates: func(ctx context.Context, tenantID shared.ID, created []asset.CreatedPasteAsset) error {
			scanned := make([]ingest.ScannedAsset, len(created))
			for i, c := range created {
				scanned[i] = ingest.ScannedAsset{ID: c.ID, Name: c.Name, Type: c.Type, Created: true}
			}
			return holder.HoldImportCandidates(ctx, tenantID, scanned)
		},
	}
}
