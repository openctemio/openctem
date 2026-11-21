package ingest

// A provider shared address the one-time provider-address move archived
// (docs/architecture/provider-address-move.md) comes back when a scan reports a
// result on the address itself: it is active again, still a dependency of
// the organization's names, and the move's journal records it as revived.
// An address a person archived (no journal item of the move) stays archived.

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ProviderAddressReviver revives an address the move archived. Satisfied by
// *postgres.ProviderAddressMoveRepository.
type ProviderAddressReviver interface {
	ReviveProviderAddress(ctx context.Context, tenantID, assetID shared.ID) (bool, error)
}

// SetProviderAddressReviver wires the reviver (nil = archived addresses stay
// archived, as before).
func (s *Service) SetProviderAddressReviver(r ProviderAddressReviver) {
	s.assetProcessor.SetProviderAddressReviver(r)
}

// SetProviderAddressReviver wires the reviver on the processor.
func (p *AssetProcessor) SetProviderAddressReviver(r ProviderAddressReviver) { p.providerRevive = r }

// reviveProviderAddress revives an archived address asset a report names
// directly when the move archived it. Best effort: a failed lookup is logged
// and the asset keeps its status, as before.
func (p *AssetProcessor) reviveProviderAddress(ctx context.Context, tenantID shared.ID, a *asset.Asset) {
	if p.providerRevive == nil || a.Status() != asset.StatusArchived || a.Type() != asset.AssetTypeIPAddress {
		return
	}
	revived, err := p.providerRevive.ReviveProviderAddress(ctx, tenantID, a.ID())
	if err != nil {
		p.logger.Warn("failed to revive a provider address", "asset_id", a.ID().String(), "error", err)
		return
	}
	if revived {
		a.Activate()
	}
}
