package asset

// Asset risk score freshness (docs/architecture/asset-risk-score.md).
// Database triggers queue an asset whenever an input of its risk score
// changes (findings created, updated, resolved or deleted by any path;
// criticality, exposure and business-context changes). ProcessRiskQueue
// claims queued assets in batches, regroups them per tenant and rescores
// each tenant's assets with that tenant's scoring settings.

import (
	"context"
	"errors"
	"fmt"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DefaultRiskQueueBatch is how many queued assets one ProcessRiskQueue call
// claims.
const DefaultRiskQueueBatch = 1000

// AssetBatchReader loads several assets of one tenant by id
// (postgres.AssetRepository). Deleted assets and ids of another tenant are
// not returned.
type AssetBatchReader interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*assetdom.Asset, error)
}

// ControlReductionLookup returns the strongest active, effective
// compensating-control reduction (0-1) per asset of one tenant
// (postgres.CompensatingControlLookupRepo).
type ControlReductionLookup interface {
	GetEffectiveForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]float64, error)
}

// SetControlReductionLookup wires compensating controls into scoring.
func (s *AssetService) SetControlReductionLookup(l ControlReductionLookup) {
	s.controlLookup = l
}

// riskInputsMap resolves, in one lookup each, the inputs of the scores of
// the given assets of one tenant that do not live on the asset row: the
// effective criticality and the compensating-control reduction. A failed
// control lookup scores without reduction (never lower than it should).
func (s *AssetService) riskInputsMap(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset) map[shared.ID]assetdom.RiskInputs {
	eff := s.effectiveCriticalityMap(ctx, tenantID, assets)
	var reductions map[shared.ID]float64
	if s.controlLookup != nil && len(assets) > 0 {
		ids := make([]shared.ID, 0, len(assets))
		for _, a := range assets {
			ids = append(ids, a.ID())
		}
		r, err := s.controlLookup.GetEffectiveForAssets(ctx, tenantID, ids)
		if err != nil {
			s.logger.Warn("compensating control lookup failed; scoring without reduction",
				"tenant_id", tenantID.String(), "error", err.Error())
		} else {
			reductions = r
		}
	}
	out := make(map[shared.ID]assetdom.RiskInputs, len(assets))
	for _, a := range assets {
		out[a.ID()] = assetdom.RiskInputs{EffectiveCriticality: eff[a.ID()], ControlReduction: reductions[a.ID()]}
	}
	return out
}

// SetRiskQueue wires the rescore queue and the batch reader it rescores with.
func (s *AssetService) SetRiskQueue(q assetdom.RiskQueueRepository, reader AssetBatchReader) {
	s.riskQueue = q
	s.riskReader = reader
}

// SetScoringVersions wires the scoring version source; each rescored asset
// stores the version it was computed with (docs/architecture/scoring-versions.md).
func (s *AssetService) SetScoringVersions(v scoring.VersionRepository) {
	s.scoringVersions = v
}

// RiskQueueResult reports one ProcessRiskQueue call.
type RiskQueueResult struct {
	Claimed int // assets taken from the queue
	Scored  int // assets whose score was computed
	Changed int // assets whose stored score changed (or got its first score)
}

// ProcessRiskQueue claims up to limit queued assets and rescores them. A
// tenant whose rescore fails has its assets queued again, and the other
// tenants are still processed; the joined error reports every failure.
func (s *AssetService) ProcessRiskQueue(ctx context.Context, limit int) (RiskQueueResult, error) {
	var res RiskQueueResult
	if s.riskQueue == nil || s.riskReader == nil {
		return res, nil
	}
	if limit <= 0 {
		limit = DefaultRiskQueueBatch
	}
	items, err := s.riskQueue.ClaimForPlatform(ctx, limit)
	if err != nil {
		return res, err
	}
	res.Claimed = len(items)

	byTenant := make(map[shared.ID][]shared.ID)
	order := make([]shared.ID, 0)
	for _, it := range items {
		if _, ok := byTenant[it.TenantID]; !ok {
			order = append(order, it.TenantID)
		}
		byTenant[it.TenantID] = append(byTenant[it.TenantID], it.AssetID)
	}

	var errs []error
	for _, tid := range order {
		ids := byTenant[tid]
		scored, changed, err := s.rescoreAssets(ctx, tid, ids)
		res.Scored += scored
		res.Changed += changed
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tid, err))
			// Put the assets back so the next tick retries them. Use a
			// fresh context: the claim already removed them, and a
			// canceled tick must not lose them.
			requeueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if qerr := s.riskQueue.Enqueue(requeueCtx, tid, ids); qerr != nil {
				errs = append(errs, fmt.Errorf("tenant %s requeue: %w", tid, qerr))
			}
			cancel()
		}
	}
	return res, errors.Join(errs...)
}

// UpdateRiskScores rescores the given assets of one tenant now.
func (s *AssetService) UpdateRiskScores(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	_, _, err := s.rescoreAssets(ctx, tenantID, assetIDs)
	return err
}

// RiskQueueStats returns the rescore queue depth and the age of its oldest
// due row (metrics).
func (s *AssetService) RiskQueueStats(ctx context.Context) (assetdom.RiskQueueStats, error) {
	if s.riskQueue == nil {
		return assetdom.RiskQueueStats{}, nil
	}
	return s.riskQueue.StatsForPlatform(ctx)
}

// EnqueueRiskReconcile queues every asset of every tenant behind the
// event-driven rows (the periodic safety net).
func (s *AssetService) EnqueueRiskReconcile(ctx context.Context, delay time.Duration) (int64, error) {
	if s.riskQueue == nil {
		return 0, nil
	}
	return s.riskQueue.EnqueueAllForPlatform(ctx, delay)
}

// rescoreAssets loads the assets of one tenant (tenant-scoped read: an id of
// another tenant, or a deleted asset, is skipped), resolves their effective
// criticality in one lookup, computes their scores and stores them in one
// batched write.
func (s *AssetService) rescoreAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (scored, changed int, err error) {
	if len(assetIDs) == 0 {
		return 0, 0, nil
	}
	if s.riskReader == nil {
		return 0, 0, errors.New("risk rescore is not configured")
	}
	byID, err := s.riskReader.GetByIDs(ctx, tenantID, assetIDs)
	if err != nil {
		return 0, 0, fmt.Errorf("load assets: %w", err)
	}
	if len(byID) == 0 {
		return 0, 0, nil
	}
	assets := make([]*assetdom.Asset, 0, len(byID))
	for _, a := range byID {
		assets = append(assets, a)
	}
	// The version is read before the settings, so the stamp is never newer
	// than the settings the scores were computed with.
	var version int64
	if s.scoringVersions != nil {
		version, err = s.scoringVersions.CurrentVersion(ctx, tenantID, scoring.KindAssetRisk)
		if err != nil {
			return 0, 0, err
		}
	}
	config := s.getScoringConfigAt(ctx, tenantID, version)
	engine := assetdom.NewRiskScoringEngine(*config)
	inputs := s.riskInputsMap(ctx, tenantID, assets)

	write := make([]*assetdom.Asset, 0, len(assets))
	for _, a := range assets {
		old := a.RiskScore()
		in := inputs[a.ID()]
		score := engine.CalculateScoreWithInputs(a, in)
		scored++
		if score != old || a.RiskScoredAt() == nil {
			a.CalculateRiskScoreWithInputs(config, in)
			write = append(write, a)
		}
	}
	if len(write) > 0 {
		if err := s.repo.BatchUpdateRiskScores(ctx, tenantID, write); err != nil {
			return scored, 0, fmt.Errorf("store risk scores: %w", err)
		}
	}
	// The unit and group roll-ups follow every rescore: a finding change can
	// move their open-finding counts even when no score changed.
	if s.riskQueue != nil {
		ids := make([]shared.ID, 0, len(assets))
		for _, a := range assets {
			ids = append(ids, a.ID())
		}
		if version > 0 {
			if err := s.riskQueue.StampRiskVersion(ctx, tenantID, ids, version); err != nil {
				return scored, len(write), fmt.Errorf("stamp risk version: %w", err)
			}
		}
		if err := s.riskQueue.RefreshRollups(ctx, tenantID, ids); err != nil {
			s.logger.Warn("risk roll-up refresh failed", "tenant_id", tenantID.String(), "error", err.Error())
		}
	}
	return scored, len(write), nil
}

// SetRiskContributorReader wires the reader behind the score explanation.
func (s *AssetService) SetRiskContributorReader(r assetdom.RiskContributorReader) {
	s.riskContributors = r
}

// RiskExplanation explains an asset's risk score.
type RiskExplanation struct {
	Asset        *assetdom.Asset
	Level        string
	Breakdown    assetdom.RiskBreakdown
	Contributors []assetdom.RiskContributor
	RiskLevels   assetdom.RiskLevelMap
}

// riskContributorLimit is how many findings the explanation lists.
const riskContributorLimit = 5

// ExplainRisk explains the risk score of one asset the caller may see (the
// same tenant and data-scope check as reading the asset; out of scope is
// not found). The breakdown is computed now from the current inputs, so it
// may already differ from a stored score whose rescore is still queued.
func (s *AssetService) ExplainRisk(ctx context.Context, tenantID, assetID, actingUserID string, isAdmin bool) (*RiskExplanation, error) {
	a, err := s.GetAssetWithScope(ctx, tenantID, assetID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	tid := a.TenantID()
	config := s.getScoringConfig(ctx, tid)
	engine := assetdom.NewRiskScoringEngine(*config)
	in := s.riskInputsMap(ctx, tid, []*assetdom.Asset{a})[a.ID()]
	b := engine.Explain(a, in)
	out := &RiskExplanation{
		Asset:      a,
		Breakdown:  b,
		Level:      config.Level(a.RiskScore()),
		RiskLevels: config.RiskLevels,
	}
	if s.riskContributors != nil {
		c, err := s.riskContributors.TopContributors(ctx, tid, a.ID(), riskContributorLimit)
		if err != nil {
			return nil, fmt.Errorf("risk contributors: %w", err)
		}
		out.Contributors = c
	}
	return out, nil
}
