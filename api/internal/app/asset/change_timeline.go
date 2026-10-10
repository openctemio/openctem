package asset

// Asset change timeline (RFC-069 §11,
// docs/architecture/asset-attribute-reconciliation.md): what changed on an
// asset, when, from which source and why. Reads only; events are written
// with the change itself.

import (
	"context"
	"fmt"
	"time"

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

// AttributeSourceLister pages the tenant's assets that have a recorded
// source (*postgres.AssetChangeEventRepository).
type AttributeSourceLister interface {
	AssetsWithAttributeSources(ctx context.Context, tenantID shared.ID, after *shared.ID, limit int) ([]shared.ID, error)
}

// SetAttributeSourceLister wires bulk re-resolution.
func (s *AssetService) SetAttributeSourceLister(l AttributeSourceLister) { s.attrLister = l }

// reResolveBatch is how many assets one re-resolution transaction locks.
const reResolveBatch = 200

// ReResolveTenant re-resolves the reconciled attributes of every asset of
// the tenant with a recorded source, in batches, and returns how many values
// changed. reason is the timeline reason when the record that decided
// before does not explain the change.
func (s *AssetService) ReResolveTenant(ctx context.Context, tenantID shared.ID, reason assetdom.ChangeReason) (int, error) {
	if s.attrLister == nil || s.attrSources == nil {
		return 0, nil
	}
	changed := 0
	var after *shared.ID
	for {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		ids, err := s.attrLister.AssetsWithAttributeSources(ctx, tenantID, after, reResolveBatch)
		if err != nil {
			return changed, err
		}
		if len(ids) == 0 {
			return changed, nil
		}
		n, err := s.ResolveAttributes(ctx, tenantID, ids, reason)
		if err != nil {
			return changed, err
		}
		changed += n
		if len(ids) < reResolveBatch {
			return changed, nil
		}
		last := ids[len(ids)-1]
		after = &last
	}
}

// AssetPolicyChanged re-resolves the tenant's assets in the background after
// its source precedence changed. A change while a run is going schedules one
// more run.
func (s *AssetService) AssetPolicyChanged(tenantID shared.ID) {
	if _, running := s.reresolving.LoadOrStore(tenantID, true); running {
		s.reresolveAgain.Store(tenantID, true)
		return
	}
	go func() {
		defer s.reresolving.Delete(tenantID)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			n, err := s.ReResolveTenant(ctx, tenantID, assetdom.ChangeReasonPolicyChange)
			cancel()
			if err != nil {
				s.logger.Warn("asset re-resolution after a precedence change failed", "tenant_id", tenantID.String(), "error", err)
			} else {
				s.logger.Info("assets re-resolved after a precedence change", "tenant_id", tenantID.String(), "changed", n)
			}
			if _, again := s.reresolveAgain.LoadAndDelete(tenantID); !again {
				return
			}
		}
	}()
}
