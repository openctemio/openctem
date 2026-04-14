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
//   - Subdomain -> parent domain: member_of relationship
//   - Domain/subdomain with resolved_ip -> IP address asset: resolves_to relationship
func (s *RelationshipSuggestionService) GenerateSuggestions(ctx context.Context, tenantID string) (int, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	s.logger.Info("generating relationship suggestions", "tenant_id", tenantID)

	// Clean up stale pending suggestions before regenerating.
	// This ensures re-scan picks up logic changes (e.g., cname_of → member_of).
	if cleanErr := s.suggestionRepo.DeletePending(ctx, parsedTenantID); cleanErr != nil {
		s.logger.Warn("failed to clean pending suggestions", "error", cleanErr)
	}

	// Fetch all domains
	domainFilter := asset.Filter{
		TenantID: &tenantID,
		Types:    []asset.AssetType{asset.AssetTypeDomain},
	}
	domainResult, err := s.assetRepo.List(ctx, domainFilter, asset.ListOptions{}, pagination.New(1, 100))
	if err != nil {
		return 0, fmt.Errorf("failed to list domains: %w", err)
	}

	// Build a map of domain name -> asset for quick lookup
	domainMap := make(map[string]*asset.Asset, len(domainResult.Data))
	for _, d := range domainResult.Data {
		domainMap[d.Name()] = d
	}

	// Fetch all subdomains
	subdomainFilter := asset.Filter{
		TenantID: &tenantID,
		Types:    []asset.AssetType{asset.AssetTypeSubdomain},
	}
	subdomainResult, err := s.assetRepo.List(ctx, subdomainFilter, asset.ListOptions{}, pagination.New(1, 100))
	if err != nil {
		return 0, fmt.Errorf("failed to list subdomains: %w", err)
	}

	// Fetch all IP address assets for resolves_to suggestions
	ipFilter := asset.Filter{
		TenantID: &tenantID,
		Types:    []asset.AssetType{asset.AssetTypeIPAddress},
	}
	ipResult, err := s.assetRepo.List(ctx, ipFilter, asset.ListOptions{}, pagination.New(1, 100))
	if err != nil {
		return 0, fmt.Errorf("failed to list IP addresses: %w", err)
	}

	// Build IP name -> asset map
	ipMap := make(map[string]*asset.Asset, len(ipResult.Data))
	for _, ip := range ipResult.Data {
		ipMap[ip.Name()] = ip
	}

	suggestions := make([]*relationship.Suggestion, 0)

	// Generate subdomain -> domain (member_of) suggestions
	for _, sub := range subdomainResult.Data {
		parentDomain := findParentDomain(sub.Name(), domainMap)
		if parentDomain != nil {
			suggestion, suggErr := relationship.NewSuggestion(
				parsedTenantID,
				sub.ID(),
				parentDomain.ID(),
				string(asset.RelTypeCnameOf),
				fmt.Sprintf("Subdomain %s belongs to domain %s", sub.Name(), parentDomain.Name()),
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
	allDNSAssets := make([]*asset.Asset, 0, len(domainResult.Data)+len(subdomainResult.Data))
	allDNSAssets = append(allDNSAssets, domainResult.Data...)
	allDNSAssets = append(allDNSAssets, subdomainResult.Data...)

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
func (s *RelationshipSuggestionService) ApproveBatch(ctx context.Context, tenantID string, ids []string, reviewerID string) (int, error) {
	approved := 0
	for _, id := range ids {
		if err := s.Approve(ctx, tenantID, id, reviewerID); err != nil {
			s.logger.Warn("failed to approve suggestion in batch", "id", id, "error", err)
			continue
		}
		approved++
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

// isAlreadyExists checks if an error is an "already exists" error.
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
