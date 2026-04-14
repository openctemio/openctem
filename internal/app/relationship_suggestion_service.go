package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/relationship"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// RelationshipSuggestionService handles relationship suggestion business logic.
type RelationshipSuggestionService struct {
	suggestionRepo relationship.SuggestionRepository
	assetRepo      asset.Repository
	relRepo        asset.RelationshipRepository
	logger         *logger.Logger
}

// NewRelationshipSuggestionService creates a new RelationshipSuggestionService.
func NewRelationshipSuggestionService(
	suggestionRepo relationship.SuggestionRepository,
	assetRepo asset.Repository,
	relRepo asset.RelationshipRepository,
	log *logger.Logger,
) *RelationshipSuggestionService {
	return &RelationshipSuggestionService{
		suggestionRepo: suggestionRepo,
		assetRepo:      assetRepo,
		relRepo:        relRepo,
		logger:         log.With("service", "relationship_suggestion"),
	}
}

// GenerateSuggestions analyzes assets and generates relationship suggestions.
// It creates suggestions for:
//   - Domain contains subdomain: contains relationship (parent → child)
//   - Domain/subdomain with resolved_ip -> IP address asset: resolves_to relationship
func (s *RelationshipSuggestionService) GenerateSuggestions(ctx context.Context, tenantID string) (int, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	s.logger.Info("generating relationship suggestions", "tenant_id", tenantID)

	// Clean up stale pending suggestions before regenerating.
	if cleanErr := s.suggestionRepo.DeletePending(ctx, parsedTenantID); cleanErr != nil {
		s.logger.Warn("failed to clean pending suggestions", "error", cleanErr)
	}

	// Fetch all assets by type using pagination loop to handle large datasets.
	domains, err := s.fetchAllAssets(ctx, tenantID, asset.AssetTypeDomain)
	if err != nil {
		return 0, fmt.Errorf("failed to list domains: %w", err)
	}

	subdomains, err := s.fetchAllAssets(ctx, tenantID, asset.AssetTypeSubdomain)
	if err != nil {
		return 0, fmt.Errorf("failed to list subdomains: %w", err)
	}

	ips, err := s.fetchAllAssets(ctx, tenantID, asset.AssetTypeIPAddress)
	if err != nil {
		return 0, fmt.Errorf("failed to list IP addresses: %w", err)
	}

	// Build lookup maps
	domainMap := make(map[string]*asset.Asset, len(domains))
	for _, d := range domains {
		domainMap[d.Name()] = d
	}

	ipMap := make(map[string]*asset.Asset, len(ips))
	for _, ip := range ips {
		ipMap[ip.Name()] = ip
	}

	suggestions := make([]*relationship.Suggestion, 0)

	// Generate domain contains subdomain suggestions (parent → child)
	for _, sub := range subdomains {
		parentDomain := findParentDomain(sub.Name(), domainMap)
		if parentDomain != nil {
			suggestion, suggErr := relationship.NewSuggestion(
				parsedTenantID,
				parentDomain.ID(),
				sub.ID(),
				string(asset.RelTypeContains),
				fmt.Sprintf("Domain %s contains subdomain %s", parentDomain.Name(), sub.Name()),
				0.95,
			)
			if suggErr != nil {
				s.logger.Warn("failed to create member_of suggestion", "error", suggErr)
				continue
			}
			suggestions = append(suggestions, suggestion)
		}
	}

	// Generate resolves_to suggestions for domains/subdomains with resolved_ip
	allDNSAssets := make([]*asset.Asset, 0, len(domains)+len(subdomains))
	allDNSAssets = append(allDNSAssets, domains...)
	allDNSAssets = append(allDNSAssets, subdomains...)

	for _, dnsAsset := range allDNSAssets {
		resolvedIP := getResolvedIP(dnsAsset)
		if resolvedIP == "" {
			continue
		}

		ipAsset, found := ipMap[resolvedIP]
		if !found {
			continue
		}

		suggestion, suggErr := relationship.NewSuggestion(
			parsedTenantID,
			dnsAsset.ID(),
			ipAsset.ID(),
			string(asset.RelTypeResolvesTo),
			fmt.Sprintf("%s resolves to IP %s", dnsAsset.Name(), resolvedIP),
			0.90,
		)
		if suggErr != nil {
			s.logger.Warn("failed to create resolves_to suggestion", "error", suggErr)
			continue
		}
		suggestions = append(suggestions, suggestion)
	}

	if len(suggestions) == 0 {
		s.logger.Info("no suggestions generated", "tenant_id", tenantID)
		return 0, nil
	}

	created, err := s.suggestionRepo.CreateBatch(ctx, suggestions)
	if err != nil {
		return 0, fmt.Errorf("failed to create suggestions: %w", err)
	}

	s.logger.Info("suggestions generated", "tenant_id", tenantID, "total", len(suggestions), "created", created)
	return created, nil
}

// ListPending returns pending suggestions for a tenant, optionally filtered by search.
func (s *RelationshipSuggestionService) ListPending(ctx context.Context, tenantID string, search string, page pagination.Pagination) (pagination.Result[*relationship.Suggestion], error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[*relationship.Suggestion]{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	return s.suggestionRepo.ListPending(ctx, parsedTenantID, search, page)
}

// ApproveBatch approves multiple suggestions by IDs.
// Returns (approved count, error). Returns error only if ALL items failed.
func (s *RelationshipSuggestionService) ApproveBatch(ctx context.Context, tenantID string, ids []string, reviewerID string) (int, error) {
	const maxBatchSize = 1000
	if len(ids) > maxBatchSize {
		return 0, fmt.Errorf("%w: batch size exceeds maximum of %d", shared.ErrValidation, maxBatchSize)
	}

	approved := 0
	for _, id := range ids {
		if err := s.Approve(ctx, tenantID, id, reviewerID); err != nil {
			s.logger.Warn("failed to approve suggestion in batch", "id", id, "error", err)
			continue
		}
		approved++
	}

	if approved == 0 && len(ids) > 0 {
		return 0, fmt.Errorf("failed to approve any of the %d suggestions", len(ids))
	}

	return approved, nil
}

// Approve approves a suggestion and creates the real relationship.
func (s *RelationshipSuggestionService) Approve(ctx context.Context, tenantID, suggestionID, reviewerID string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedSuggestionID, err := shared.IDFromString(suggestionID)
	if err != nil {
		return fmt.Errorf("%w: invalid suggestion ID", shared.ErrValidation)
	}
	parsedReviewerID, err := shared.IDFromString(reviewerID)
	if err != nil {
		return fmt.Errorf("%w: invalid reviewer ID", shared.ErrValidation)
	}

	// Fetch the suggestion
	suggestion, err := s.suggestionRepo.GetByID(ctx, parsedTenantID, parsedSuggestionID)
	if err != nil {
		return err
	}

	if suggestion.Status() != relationship.SuggestionPending {
		return fmt.Errorf("%w: suggestion is not pending", shared.ErrValidation)
	}

	// Create the real relationship
	relType, parseErr := asset.ParseRelationshipType(suggestion.RelationshipType())
	if parseErr != nil {
		return fmt.Errorf("invalid relationship type in suggestion: %w", parseErr)
	}

	rel, relErr := asset.NewRelationship(
		parsedTenantID,
		suggestion.SourceAssetID(),
		suggestion.TargetAssetID(),
		relType,
	)
	if relErr != nil {
		return fmt.Errorf("failed to create relationship from suggestion: %w", relErr)
	}
	rel.SetDescription(suggestion.Reason())

	if createErr := s.relRepo.Create(ctx, rel); createErr != nil {
		// If relationship already exists, still mark suggestion as approved
		if !isAlreadyExists(createErr) {
			return fmt.Errorf("failed to persist relationship: %w", createErr)
		}
		s.logger.Info("relationship already exists, marking suggestion as approved", "suggestion_id", suggestionID)
	}

	// Mark as approved
	suggestion.Approve(parsedReviewerID)
	if updateErr := s.suggestionRepo.UpdateStatus(ctx, suggestion); updateErr != nil {
		return fmt.Errorf("failed to update suggestion status: %w", updateErr)
	}

	return nil
}

// ApproveAll approves all pending suggestions and creates relationships for each.
func (s *RelationshipSuggestionService) ApproveAll(ctx context.Context, tenantID, reviewerID string) (int, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedReviewerID, err := shared.IDFromString(reviewerID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid reviewer ID", shared.ErrValidation)
	}

	// Approve all in DB and get the approved suggestions
	approved, err := s.suggestionRepo.ApproveAll(ctx, parsedTenantID, parsedReviewerID)
	if err != nil {
		return 0, fmt.Errorf("failed to approve all suggestions: %w", err)
	}

	// Create relationships for each approved suggestion
	created := 0
	for _, suggestion := range approved {
		relType, parseErr := asset.ParseRelationshipType(suggestion.RelationshipType())
		if parseErr != nil {
			s.logger.Warn("skipping suggestion with invalid relationship type", "suggestion_id", suggestion.ID().String(), "type", suggestion.RelationshipType())
			continue
		}

		rel, relErr := asset.NewRelationship(
			parsedTenantID,
			suggestion.SourceAssetID(),
			suggestion.TargetAssetID(),
			relType,
		)
		if relErr != nil {
			s.logger.Warn("failed to create relationship from suggestion", "suggestion_id", suggestion.ID().String(), "error", relErr)
			continue
		}
		rel.SetDescription(suggestion.Reason())

		if createErr := s.relRepo.Create(ctx, rel); createErr != nil {
			if !isAlreadyExists(createErr) {
				s.logger.Warn("failed to persist relationship", "suggestion_id", suggestion.ID().String(), "error", createErr)
			}
			continue
		}
		created++
	}

	s.logger.Info("bulk approved suggestions", "tenant_id", tenantID, "approved", len(approved), "relationships_created", created)
	return len(approved), nil
}

// UpdateRelationshipType changes the relationship type of a pending suggestion.
func (s *RelationshipSuggestionService) UpdateRelationshipType(ctx context.Context, tenantID, suggestionID, relType string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedSuggestionID, err := shared.IDFromString(suggestionID)
	if err != nil {
		return fmt.Errorf("%w: invalid suggestion ID", shared.ErrValidation)
	}
	if relType == "" {
		return fmt.Errorf("%w: relationship type is required", shared.ErrValidation)
	}
	// Validate the relationship type is valid
	if _, parseErr := asset.ParseRelationshipType(relType); parseErr != nil {
		return fmt.Errorf("%w: invalid relationship type: %s", shared.ErrValidation, relType)
	}

	return s.suggestionRepo.UpdateRelationshipType(ctx, parsedTenantID, parsedSuggestionID, relType)
}

// Dismiss marks a suggestion as dismissed.
func (s *RelationshipSuggestionService) Dismiss(ctx context.Context, tenantID, suggestionID, reviewerID string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	parsedSuggestionID, err := shared.IDFromString(suggestionID)
	if err != nil {
		return fmt.Errorf("%w: invalid suggestion ID", shared.ErrValidation)
	}
	parsedReviewerID, err := shared.IDFromString(reviewerID)
	if err != nil {
		return fmt.Errorf("%w: invalid reviewer ID", shared.ErrValidation)
	}

	suggestion, err := s.suggestionRepo.GetByID(ctx, parsedTenantID, parsedSuggestionID)
	if err != nil {
		return err
	}

	if suggestion.Status() != relationship.SuggestionPending {
		return fmt.Errorf("%w: suggestion is not pending", shared.ErrValidation)
	}

	suggestion.Dismiss(parsedReviewerID)
	return s.suggestionRepo.UpdateStatus(ctx, suggestion)
}

// CountPending returns the number of pending suggestions for a tenant.
func (s *RelationshipSuggestionService) CountPending(ctx context.Context, tenantID string) (int64, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	return s.suggestionRepo.CountPending(ctx, parsedTenantID)
}

// =============================================================================
// Helpers
// =============================================================================

// findParentDomain extracts the parent domain from a subdomain name and looks it up.
// Example: "api.example.com" -> look for "example.com" in the map.
func findParentDomain(subdomainName string, domainMap map[string]*asset.Asset) *asset.Asset {
	parts := strings.SplitN(subdomainName, ".", 2)
	if len(parts) < 2 {
		return nil
	}
	parentName := parts[1]

	// Direct lookup
	if parent, ok := domainMap[parentName]; ok {
		return parent
	}

	// Try further up the hierarchy (e.g., "a.b.example.com" -> "b.example.com" -> "example.com")
	for {
		parts = strings.SplitN(parentName, ".", 2)
		if len(parts) < 2 {
			break
		}
		parentName = parts[1]
		if parent, ok := domainMap[parentName]; ok {
			return parent
		}
	}

	return nil
}

// getResolvedIP extracts the resolved_ip property from an asset.
func getResolvedIP(a *asset.Asset) string {
	props := a.Properties()

	// Check resolved_ip property
	if ip, ok := props["resolved_ip"]; ok {
		if ipStr, ok := ip.(string); ok && ipStr != "" {
			return ipStr
		}
	}

	// Check resolved_ips (array — take the first)
	if ips, ok := props["resolved_ips"]; ok {
		switch v := ips.(type) {
		case []any:
			if len(v) > 0 {
				if ipStr, ok := v[0].(string); ok {
					return ipStr
				}
			}
		case []string:
			if len(v) > 0 {
				return v[0]
			}
		}
	}

	return ""
}

// fetchAllAssets retrieves all assets of a given type for a tenant, paginating through all pages.
// This prevents the LIMIT 100 cap from silently truncating large datasets.
func (s *RelationshipSuggestionService) fetchAllAssets(ctx context.Context, tenantID string, assetType asset.AssetType) ([]*asset.Asset, error) {
	const pageSize = 100
	filter := asset.Filter{
		TenantID: &tenantID,
		Types:    []asset.AssetType{assetType},
	}

	var all []*asset.Asset
	for page := 1; ; page++ {
		result, err := s.assetRepo.List(ctx, filter, asset.ListOptions{}, pagination.New(page, pageSize))
		if err != nil {
			return nil, err
		}
		all = append(all, result.Data...)
		if len(all) >= int(result.Total) || len(result.Data) < pageSize {
			break
		}
	}
	return all, nil
}

// isAlreadyExists checks if an error is an "already exists" error.
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
