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

// SetRiskQueue wires the rescore queue and the batch reader it rescores with.
func (s *AssetService) SetRiskQueue(q assetdom.RiskQueueRepository, reader AssetBatchReader) {
	s.riskQueue = q
	s.riskReader = reader
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
	config := s.getScoringConfig(ctx, tenantID)
	engine := assetdom.NewRiskScoringEngine(*config)
	eff := s.effectiveCriticalityMap(ctx, tenantID, assets)

	write := make([]*assetdom.Asset, 0, len(assets))
	for _, a := range assets {
		old := a.RiskScore()
		score := engine.CalculateScoreWithCriticality(a, eff[a.ID()])
		scored++
		if score != old || a.RiskScoredAt() == nil {
			a.CalculateRiskScoreWithConfigAndCriticality(config, eff[a.ID()])
			write = append(write, a)
		}
	}
	if len(write) == 0 {
		return scored, 0, nil
	}
	if err := s.repo.BatchUpdateRiskScores(ctx, tenantID, write); err != nil {
		return scored, 0, fmt.Errorf("store risk scores: %w", err)
	}
	return scored, len(write), nil
}
