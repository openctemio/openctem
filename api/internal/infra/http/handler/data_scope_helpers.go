package handler

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DataScopeEnforcer is the slice of the Layer 2 data-scope enforcer
// (*datascope.Enforcer) that handlers reading asset-bound rows straight from
// a repository need. Resolve returns the caller's scope (nil when
// unrestricted); AssertAsset returns shared.ErrNotFound unless the caller may
// see the asset.
type DataScopeEnforcer interface {
	Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
	AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error
}

// resolveDataScope returns the caller's data scope, or nil when no enforcer
// is wired (unrestricted, as before data scope existed).
func resolveDataScope(ctx context.Context, e DataScopeEnforcer, tenantID shared.ID) (*shared.DataScope, error) {
	if e == nil {
		return nil, nil
	}
	return e.Resolve(ctx, tenantID)
}

// assetInDataScope reports whether the caller may see the asset. Any error
// while checking denies (fail closed).
func assetInDataScope(ctx context.Context, e DataScopeEnforcer, tenantID, assetID shared.ID) bool {
	if e == nil {
		return true
	}
	return e.AssertAsset(ctx, tenantID, assetID) == nil
}
