package asset

// Asset change timeline (RFC-069 §11,
// docs/architecture/asset-attribute-reconciliation.md): what changed on an
// asset, when, from which source and why. Reads only; events are written
// with the change itself.

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetChangeTimeline wires the timeline reads. Unwired, they return nothing.
func (s *AssetService) SetChangeTimeline(repo assetdom.ChangeEventRepository) {
	s.changes = repo
}

// ListAssetChanges returns a page of the timeline of an asset the caller
// may see (out of scope: not found), newest first.
func (s *AssetService) ListAssetChanges(ctx context.Context, tenantID, assetID string, q assetdom.ChangeQuery) ([]assetdom.ChangeEvent, bool, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, false, err
	}
	if s.changes == nil {
		return nil, false, nil
	}
	id := a.ID()
	q.AssetID = &id
	q.ScopeUserID = nil
	q.Tag = ""
	return s.changes.ListChanges(ctx, a.TenantID(), q)
}

// ListTenantChanges returns a page of the organization's recent asset
// changes, limited to the assets the caller may see.
func (s *AssetService) ListTenantChanges(ctx context.Context, tenantID string, q assetdom.ChangeQuery) ([]assetdom.ChangeEvent, bool, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, false, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.changes == nil {
		return nil, false, nil
	}
	q.AssetID = nil
	q.ScopeUserID = nil
	if s.dataScope != nil {
		scope, err := s.dataScope.Resolve(ctx, tid)
		if err != nil {
			return nil, false, err
		}
		if scope != nil {
			uid := scope.UserID
			q.ScopeUserID = &uid
		}
	}
	return s.changes.ListChanges(ctx, tid, q)
}
