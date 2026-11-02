package asset

// Discovery lineage (docs/architecture/easm.md, Discovery lineage).

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetLineage wires the reader of an asset's ancestor chain. Unset, an asset
// shows only itself.
func (s *AssetService) SetLineage(r assetdom.LineageReader) { s.lineage = r }

// GetLineage returns how an asset was found: the asset and its ancestors up
// to the root, at most assetdom.LineageMaxDepth of them. The asset must be
// one the caller may see (another tenant's, or one outside the caller's data
// scope, is not found). Every ancestor is checked against the caller's data
// scope too: one outside it is returned as a hidden node with no name, id or
// type, so a restricted caller never learns the names above their scope.
func (s *AssetService) GetLineage(ctx context.Context, tenantID, assetID string) (*assetdom.Lineage, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if s.lineage == nil {
		l := assetdom.BuildLineage([]assetdom.LineageNode{selfNode(a)}, assetdom.LineageMaxDepth)
		return &l, nil
	}
	var scope *shared.DataScope
	if s.dataScope != nil {
		if scope, err = s.dataScope.Resolve(ctx, a.TenantID()); err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
	}
	rows, err := s.lineage.Lineage(ctx, a.TenantID(), a.ID(), scope, assetdom.LineageMaxDepth)
	if err != nil {
		return nil, fmt.Errorf("read asset lineage: %w", err)
	}
	if len(rows) == 0 {
		// Deleted between the check and the walk.
		return nil, shared.ErrNotFound
	}
	l := assetdom.BuildLineage(rows, assetdom.LineageMaxDepth)
	return &l, nil
}

func selfNode(a *assetdom.Asset) assetdom.LineageNode {
	first := a.FirstSeen()
	return assetdom.LineageNode{
		ID: a.ID(), Name: a.Name(), Type: a.Type(),
		DiscoverySource: a.DiscoverySource(), DiscoveryTool: a.DiscoveryTool(),
		DiscoveredAt: a.DiscoveredAt(), FirstSeen: &first,
	}
}
