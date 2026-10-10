package unit

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenantAssets is a datascope.Repository that knows which tenant owns each
// asset and nothing else (no scope rows, no full-data roles). With no user in
// the context the enforcer is unrestricted, so AssertAssetRef and
// FilterAssetRefs reduce to the tenant check.
type tenantAssets map[shared.ID]shared.ID // asset -> tenant

func (t tenantAssets) HasAnyScopeAssignment(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func (t tenantAssets) AssetIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (t tenantAssets) FindingAssetID(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return shared.ID{}, shared.ErrNotFound
}

func (t tenantAssets) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func (t tenantAssets) FindingIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (t tenantAssets) AssetIDsInTenant(_ context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if owner, ok := t[id]; ok && owner == tenantID {
			out = append(out, id)
		}
	}
	return out, nil
}

// tenantAssetEnforcer is an enforcer over tenantAssets for a context with no
// user (unrestricted, tenant check only).
func tenantAssetEnforcer(owners tenantAssets) *datascope.Enforcer {
	return datascope.New(owners, nil, logger.NewNop())
}

func (tenantAssets) HasHiddenAssets(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func (tenantAssets) AssetIDsVisible(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return ids, nil
}

func (tenantAssets) FindingIDsVisible(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return ids, nil
}
