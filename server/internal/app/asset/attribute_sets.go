package asset

// Set-valued attributes reconciled per source (RFC-069 §13,
// docs/architecture/asset-attribute-reconciliation.md): each source's
// elements of an asset's IP addresses, technologies and open ports are
// recorded with when it last saw them, and the asset shows the union of the
// trusted, fresh sources. Not observed is not removed: only the same source
// observing the same coverage without an element removes it.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// setRepo is the attribute source repository's set side, when it has one.
func (s *AssetService) setRepo() assetdom.SetElementRepository {
	r, _ := s.attrSources.(assetdom.SetElementRepository)
	return r
}

// ReconcileSets records set observations of the tenant's assets (from
// ingest) and applies the sets they decide. The caller decided each
// observation's kind from how the data arrived and its coverage from what
// the source was asked to look at.
func (s *AssetService) ReconcileSets(ctx context.Context, tenantID shared.ID, obs []assetdom.SetObservation) ([]assetdom.SetChange, error) {
	repo := s.setRepo()
	if repo == nil || len(obs) == 0 {
		return nil, nil
	}
	return s.applySets(ctx, tenantID, repo, assetdom.SetApply{Observations: obs})
}

// resolveSets re-resolves the set attributes of the tenant's assets without
// new observations (a source past its TTL, a policy change).
func (s *AssetService) resolveSets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason assetdom.ChangeReason) (int, error) {
	repo := s.setRepo()
	if repo == nil || len(assetIDs) == 0 {
		return 0, nil
	}
	refs := make([]assetdom.SetRef, 0, len(assetIDs)*len(assetdom.AllSetAttributes()))
	for _, id := range assetIDs {
		for _, attr := range assetdom.AllSetAttributes() {
			refs = append(refs, assetdom.SetRef{AssetID: id, Attribute: attr})
		}
	}
	changes, err := s.applySets(ctx, tenantID, repo, assetdom.SetApply{Resolve: refs, Reason: reason})
	return len(changes), err
}

func (s *AssetService) applySets(ctx context.Context, tenantID shared.ID, repo assetdom.SetElementRepository, in assetdom.SetApply) ([]assetdom.SetChange, error) {
	in.Policy = s.ReconciliationPolicy(ctx, tenantID)
	in.Now = time.Now()
	res, err := repo.ApplySets(ctx, tenantID, in)
	if err != nil {
		return nil, fmt.Errorf("reconcile set attributes: %w", err)
	}
	for v, n := range res.Verdicts {
		metrics.AssetAttributeObservationsTotal.WithLabelValues(string(v)).Add(float64(n))
	}
	metrics.AssetChangeEventsTotal.Add(float64(res.Events))
	return res.Changes, nil
}
