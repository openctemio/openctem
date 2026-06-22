package jira

import (
	"context"

	appjira "github.com/openctemio/api/internal/app/jira"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// assetReader is the narrow slice of the asset repository the route resolver
// needs — just enough to read a finding's asset for routing.
type assetReader interface {
	GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// AssetRouteResolver supplies a finding's asset attributes (scope, criticality)
// so ticketing routing rules can match on them. It implements
// appjira.AssetRouteResolver by loading the asset.
//
// Group memberships are not populated yet (the asset-group dimension in routing
// rules therefore never matches until that is wired) — scope/criticality cover
// the common "route the external/critical estate to project X" case.
type AssetRouteResolver struct {
	assets assetReader
}

// NewAssetRouteResolver builds the resolver from the asset repository.
func NewAssetRouteResolver(assets assetReader) *AssetRouteResolver {
	return &AssetRouteResolver{assets: assets}
}

var _ appjira.AssetRouteResolver = (*AssetRouteResolver)(nil)

// ResolveAssetRoute returns the asset's scope + criticality for routing. Groups
// are returned empty for now (see type doc).
func (r *AssetRouteResolver) ResolveAssetRoute(ctx context.Context, tenantID, assetID shared.ID) (scope, criticality string, groups []string, err error) {
	a, err := r.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return "", "", nil, err
	}
	return string(a.Scope()), string(a.Criticality()), nil, nil
}
