package datascope

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// PrimeAssets checks assetIDs for the request's caller in one query and
// remembers the allowed ones in the request memo (WithRequestMemo), so the
// AssertAsset calls that follow in the same request cost no query (a bulk
// path that checks every finding one by one). It only adds "allowed"
// answers the same check would give; an asset left out, or any error, leaves
// AssertAsset to ask as usual (fail closed). Without a memo it does nothing.
func (e *Enforcer) PrimeAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) {
	m := memoOf(ctx)
	if e == nil || m == nil || len(assetIDs) == 0 {
		return
	}
	scope, err := e.Resolve(ctx, tenantID)
	if err != nil {
		return
	}
	in, err := e.Filter(ctx, scope, assetIDs)
	if err != nil {
		return
	}
	caller := e.CallerOf(ctx)
	for _, id := range dedupe(assetIDs) {
		if in(id) {
			m.allow(verdictKey{kind: verdictAsset, tenant: tenantID, id: id, caller: caller})
		}
	}
}
