package asset

// Whole-tenant preview of a risk scoring settings change
// (docs/architecture/scoring-versions.md, "Preview before apply").

import (
	"context"
	"fmt"
	"sort"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// riskPreviewPage is how many assets one preview step scores.
const riskPreviewPage = 500

// RiskPreviewTopLimit bounds the listed assets of a preview.
const RiskPreviewTopLimit = 50

// RiskBandChange counts the assets that move from one band to another.
type RiskBandChange struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}

// RiskImpactAsset is one listed asset of a preview.
type RiskImpactAsset struct {
	AssetID      string `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	AssetType    string `json:"asset_type"`
	CurrentScore int    `json:"current_score"`
	NewScore     int    `json:"new_score"`
	CurrentLevel string `json:"current_level"`
	NewLevel     string `json:"new_level"`
}

// RiskImpact is what applying new settings would do to the tenant's assets.
// Counts cover every live asset of the tenant; the listed assets are the
// largest changes the caller may see.
type RiskImpact struct {
	TotalAssets  int               `json:"total_assets"`
	Changed      int               `json:"changed"`
	Raised       int               `json:"raised"`
	Lowered      int               `json:"lowered"`
	BandChanges  []RiskBandChange  `json:"band_changes"`
	TopChanges   []RiskImpactAsset `json:"top_changes"`
	ChangedBands int               `json:"changed_bands"`
}

// PreviewRiskImpact scores every live asset of the tenant with newConfig,
// exactly as the asset-risk-score worker will after the change is applied
// (same engine, same inputs), and compares it with the stored score and band.
// Nothing is written.
func (s *AssetService) PreviewRiskImpact(ctx context.Context, tenantID shared.ID, newConfig *assetdom.RiskScoringConfig) (*RiskImpact, error) {
	current := s.getScoringConfig(ctx, tenantID)
	engine := assetdom.NewRiskScoringEngine(*newConfig)
	filter := assetdom.NewFilter().WithTenantID(tenantID.String())
	opts := assetdom.NewListOptions().WithSort(pagination.NewSortOption(assetdom.AllowedSortFields()).Parse("created_at"))

	out := &RiskImpact{BandChanges: []RiskBandChange{}, TopChanges: []RiskImpactAsset{}}
	bands := map[[2]string]int{}
	var changed []RiskImpactAsset
	for pageNum := 1; ; pageNum++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res, err := s.repo.List(ctx, filter, opts, pagination.New(pageNum, riskPreviewPage))
		if err != nil {
			return nil, fmt.Errorf("list assets for preview: %w", err)
		}
		inputs := s.riskInputsMap(ctx, tenantID, res.Data)
		for _, a := range res.Data {
			out.TotalAssets++
			oldScore := a.RiskScore()
			newScore := engine.CalculateScoreWithInputs(a, inputs[a.ID()])
			oldLevel, newLevel := current.Level(oldScore), newConfig.Level(newScore)
			if oldLevel != newLevel {
				bands[[2]string{oldLevel, newLevel}]++
				out.ChangedBands++
			}
			if newScore == oldScore {
				continue
			}
			out.Changed++
			if newScore > oldScore {
				out.Raised++
			} else {
				out.Lowered++
			}
			changed = append(changed, RiskImpactAsset{
				AssetID: a.ID().String(), AssetName: a.Name(), AssetType: string(a.Type()),
				CurrentScore: oldScore, NewScore: newScore, CurrentLevel: oldLevel, NewLevel: newLevel,
			})
		}
		if len(res.Data) < riskPreviewPage {
			break
		}
	}
	for k, n := range bands {
		out.BandChanges = append(out.BandChanges, RiskBandChange{From: k[0], To: k[1], Count: n})
	}
	sort.Slice(out.BandChanges, func(i, j int) bool {
		if out.BandChanges[i].Count != out.BandChanges[j].Count {
			return out.BandChanges[i].Count > out.BandChanges[j].Count
		}
		return out.BandChanges[i].From+out.BandChanges[i].To < out.BandChanges[j].From+out.BandChanges[j].To
	})

	top, err := s.visibleTopChanges(ctx, tenantID, changed)
	if err != nil {
		return nil, err
	}
	out.TopChanges = top
	return out, nil
}

// visibleTopChanges returns the largest changes the caller may see: an asset
// outside the caller's data scope (a private program's asset) is counted
// but never named.
func (s *AssetService) visibleTopChanges(ctx context.Context, tenantID shared.ID, changed []RiskImpactAsset) ([]RiskImpactAsset, error) {
	sort.SliceStable(changed, func(i, j int) bool {
		return abs(changed[i].NewScore-changed[i].CurrentScore) > abs(changed[j].NewScore-changed[j].CurrentScore)
	})
	if len(changed) > 4*RiskPreviewTopLimit {
		changed = changed[:4*RiskPreviewTopLimit]
	}
	visible := func(shared.ID) bool { return true }
	if s.dataScope != nil {
		ids := make([]shared.ID, 0, len(changed))
		for _, c := range changed {
			if id, err := shared.IDFromString(c.AssetID); err == nil {
				ids = append(ids, id)
			}
		}
		f, err := s.dataScope.FilterAssetRefs(ctx, tenantID, ids)
		if err != nil {
			return nil, fmt.Errorf("preview data scope: %w", err)
		}
		visible = f
	}
	out := make([]RiskImpactAsset, 0, RiskPreviewTopLimit)
	for _, c := range changed {
		id, err := shared.IDFromString(c.AssetID)
		if err != nil || !visible(id) {
			continue
		}
		out = append(out, c)
		if len(out) == RiskPreviewTopLimit {
			break
		}
	}
	return out, nil
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// EnqueueRiskRescore queues every live asset of the tenant for the
// asset-risk-score worker (the manual "recalculate" action).
func (s *AssetService) EnqueueRiskRescore(ctx context.Context, tenantID shared.ID) (int64, error) {
	if s.riskQueue == nil {
		return 0, fmt.Errorf("%w: risk rescore is not configured", shared.ErrValidation)
	}
	return s.riskQueue.EnqueueTenant(ctx, tenantID)
}
