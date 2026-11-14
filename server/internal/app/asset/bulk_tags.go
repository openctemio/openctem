package asset

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tagdom "github.com/openctemio/openctem/server/pkg/domain/tag"
)

// MaxBulkTagAssets is the most assets one bulk tag change names; the web
// sends a larger selection in several requests.
const MaxBulkTagAssets = 100

// BulkTagChangeInput adds and removes tags on many assets. Every other tag
// of every asset stays.
type BulkTagChangeInput struct {
	AssetIDs []string
	Add      []string
	Remove   []string
	// ActorID is the person making the change.
	ActorID string
}

// BulkTagChangeResult counts what a bulk tag change did. Unchanged assets
// already carried the added tags and none of the removed ones (nothing was
// written); Failed covers ids that are malformed, of another organization,
// outside the caller's data scope or missing, without telling them apart.
type BulkTagChangeResult struct {
	Updated   int
	Unchanged int
	Failed    int
	// Changed are the ids of the updated assets.
	Changed []string
}

// BulkChangeAssetTags applies one tag change to each asset, through the
// same edit as a single asset (validation, scoring, scope and group rules),
// written as a change against each asset's stored list.
// Security: tenant from the caller; assets outside the caller's data scope
// are not touched and count as failed, like ids that do not exist.
func (s *AssetService) BulkChangeAssetTags(ctx context.Context, tenantID string, input BulkTagChangeInput) (*BulkTagChangeResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	change := tagdom.Change{Add: input.Add, Remove: input.Remove}
	if change.Empty() {
		return nil, fmt.Errorf("%w: add or remove at least one tag", shared.ErrValidation)
	}
	if len(input.AssetIDs) == 0 || len(input.AssetIDs) > MaxBulkTagAssets {
		return nil, fmt.Errorf("%w: name 1 to %d assets", shared.ErrValidation, MaxBulkTagAssets)
	}
	if err := change.Check(); err != nil {
		return nil, err
	}
	// The added tags are checked once, before any asset is written.
	if _, err := tagdom.ValidateNew(nil, input.Add); err != nil {
		return nil, tagdom.Refusal(err)
	}

	result := &BulkTagChangeResult{}
	ids := make([]shared.ID, 0, len(input.AssetIDs))
	seen := make(map[shared.ID]bool, len(input.AssetIDs))
	for _, raw := range input.AssetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			result.Failed++
			continue
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if s.dataScope != nil && len(ids) > 0 {
		inScope, err := s.dataScope.FilterForCaller(ctx, parsedTenantID, ids)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve data scope: %w", err)
		}
		kept := ids[:0]
		for _, id := range ids {
			if inScope(id) {
				kept = append(kept, id)
			} else {
				result.Failed++
			}
		}
		ids = kept
	}

	for _, id := range ids {
		a, err := s.repo.GetByID(ctx, parsedTenantID, id)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				result.Failed++
				continue
			}
			return nil, err
		}
		added, removed := tagdom.Diff(a.Tags(), tagdom.Apply(a.Tags(), change))
		if len(added)+len(removed) == 0 {
			result.Unchanged++
			continue
		}
		if _, _, err := s.updateAsset(ctx, id.String(), tenantID, UpdateAssetInput{
			TagsAdd: input.Add, TagsRemove: input.Remove, ActorID: input.ActorID,
		}, nil); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				result.Failed++
				continue
			}
			if errors.Is(err, shared.ErrValidation) {
				// This asset cannot take the change (it would pass the tag
				// cap); the others still do.
				result.Failed++
				continue
			}
			return nil, err
		}
		result.Updated++
		result.Changed = append(result.Changed, id.String())
	}
	return result, nil
}
