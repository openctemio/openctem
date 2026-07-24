package asset

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	relationshipdom "github.com/openctemio/api/pkg/domain/relationship"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// graph_enrichment.go wires the pure InferGraphEdges inference (Exposes /
// RunsOn) into the persistence layer: it loads a tenant's host/service/
// application assets, infers edges, auto-creates the unambiguous ones in the
// relationships table (idempotently), and files the ambiguous ones as
// suggestions for operator review.
//
// This is the seam that unstarves the attack-path / exposure-chain /
// reachability engines on already-ingested data — driven by the background
// GraphEnrichmentController so it enriches historical assets without slowing
// the ingest hot path.

// enrichmentAssetTypes are the asset types the enrichment reasons over. Naabu
// open ports and HTTPX services normalize to the `service` core type; hosts /
// ip_addresses are the containers; applications get RunsOn edges.
var enrichmentAssetTypes = []assetdom.AssetType{
	assetdom.AssetTypeHost,
	assetdom.AssetTypeIPAddress,
	assetdom.AssetTypeService,
	assetdom.AssetTypeApplication,
	// Legacy (pre-consolidation) application types, harmless if unused.
	assetdom.AssetTypeWebsite,
	assetdom.AssetTypeWebApplication,
	assetdom.AssetTypeAPI,
}

// EnrichGraphResult reports what a single enrichment pass produced.
type EnrichGraphResult struct {
	AssetsScanned    int
	EdgesCreated     int
	SuggestionsAdded int
}

// EnrichGraph infers and persists high-confidence asset-graph edges for one
// tenant. Auto edges are created via CreateBatchIgnoreConflicts (idempotent —
// duplicates are silently skipped); ambiguous edges are filed as suggestions
// via the same ON CONFLICT DO NOTHING batch used elsewhere, so repeated runs
// never duplicate or resurrect dismissed suggestions.
//
// Unlike GenerateSuggestions this does NOT wipe pending suggestions first — it
// is additive and safe to run continuously in the background.
func (s *RelationshipSuggestionService) EnrichGraph(ctx context.Context, tenantID string) (EnrichGraphResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return EnrichGraphResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	assets, err := s.loadEnrichmentAssets(ctx, tenantID)
	if err != nil {
		return EnrichGraphResult{}, fmt.Errorf("load assets for enrichment: %w", err)
	}
	if len(assets) == 0 {
		return EnrichGraphResult{}, nil
	}

	graph := make([]GraphAsset, 0, len(assets))
	for _, a := range assets {
		graph = append(graph, GraphAsset{
			ID:      a.ID(),
			Type:    a.Type(),
			SubType: a.SubType(),
			Name:    a.Name(),
			Props:   a.Properties(),
		})
	}

	inferred := InferGraphEdges(graph)

	result := EnrichGraphResult{AssetsScanned: len(assets)}
	result.EdgesCreated = s.persistAutoEdges(ctx, parsedTenantID, inferred.AutoEdges)
	result.SuggestionsAdded = s.persistSuggestions(ctx, parsedTenantID, inferred.Suggestions)

	if result.EdgesCreated > 0 || result.SuggestionsAdded > 0 {
		s.logger.Info("graph enrichment applied",
			"tenant_id", tenantID,
			"assets_scanned", result.AssetsScanned,
			"edges_created", result.EdgesCreated,
			"suggestions_added", result.SuggestionsAdded,
		)
	}
	return result, nil
}

// persistAutoEdges materializes unambiguous inferred edges as real
// relationships. Returns the number actually created (conflicts skipped).
func (s *RelationshipSuggestionService) persistAutoEdges(ctx context.Context, tenantID shared.ID, edges []InferredEdge) int {
	if len(edges) == 0 {
		return 0
	}
	rels := make([]*assetdom.Relationship, 0, len(edges))
	for _, e := range edges {
		rel, relErr := assetdom.NewRelationship(tenantID, e.SourceID, e.TargetID, e.Type)
		if relErr != nil {
			s.logger.Warn("failed to build inferred relationship", "type", e.Type, "error", relErr)
			continue
		}
		rel.SetDescription(e.Reason)
		_ = rel.SetConfidence(e.Confidence)
		_ = rel.SetDiscoveryMethod(assetdom.DiscoveryInferred)
		rels = append(rels, rel)
	}
	if len(rels) == 0 {
		return 0
	}
	created, err := s.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		s.logger.Warn("failed to persist inferred relationships", "count", len(rels), "error", err)
		return 0
	}
	return created
}

// persistSuggestions files ambiguous inferred edges for operator review.
func (s *RelationshipSuggestionService) persistSuggestions(ctx context.Context, tenantID shared.ID, edges []InferredEdge) int {
	if len(edges) == 0 {
		return 0
	}
	suggestions := make([]*relationshipdom.Suggestion, 0, len(edges))
	for _, e := range edges {
		sg, sgErr := relationshipdom.NewSuggestion(
			tenantID, e.SourceID, e.TargetID, string(e.Type), e.Reason, confidenceToFloat(e.Confidence),
		)
		if sgErr != nil {
			s.logger.Warn("failed to build inferred suggestion", "type", e.Type, "error", sgErr)
			continue
		}
		suggestions = append(suggestions, sg)
	}
	if len(suggestions) == 0 {
		return 0
	}
	created, err := s.suggestionRepo.CreateBatch(ctx, suggestions)
	if err != nil {
		s.logger.Warn("failed to persist inferred suggestions", "count", len(suggestions), "error", err)
		return 0
	}
	return created
}

// loadEnrichmentAssets fetches every enrichment-relevant asset for the tenant,
// paginating so large tenants are not silently truncated.
func (s *RelationshipSuggestionService) loadEnrichmentAssets(ctx context.Context, tenantID string) ([]*assetdom.Asset, error) {
	const pageSize = 200
	filter := assetdom.Filter{
		TenantID: &tenantID,
		Types:    enrichmentAssetTypes,
	}

	var all []*assetdom.Asset
	for page := 1; ; page++ {
		res, err := s.assetRepo.List(ctx, filter, assetdom.ListOptions{}, pagination.New(page, pageSize))
		if err != nil {
			return nil, err
		}
		all = append(all, res.Data...)
		if len(all) >= int(res.Total) || len(res.Data) < pageSize {
			break
		}
	}
	return all, nil
}

// confidenceToFloat maps the domain confidence level to the 0..1 score the
// suggestion entity stores.
func confidenceToFloat(c assetdom.RelationshipConfidence) float64 {
	switch c {
	case assetdom.ConfidenceHigh:
		return 0.9
	case assetdom.ConfidenceMedium:
		return 0.6
	default:
		return 0.4
	}
}
