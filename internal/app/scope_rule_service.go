package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ScopeRuleService handles scope rule business operations.
type ScopeRuleService struct {
	acRepo    accesscontrol.Repository
	groupRepo group.Repository
	logger    *logger.Logger
}

// NewScopeRuleService creates a new ScopeRuleService.
func NewScopeRuleService(
	acRepo accesscontrol.Repository,
	groupRepo group.Repository,
	log *logger.Logger,
) *ScopeRuleService {
	return &ScopeRuleService{
		acRepo:    acRepo,
		groupRepo: groupRepo,
		logger:    log.With("service", "scope_rule"),
	}
}

// CreateScopeRuleInput represents the input for creating a scope rule.
type CreateScopeRuleInput struct {
	GroupID            string   `json:"-"`
	TenantID           string   `json:"-"`
	Name               string   `json:"name" validate:"required,min=2,max=200"`
	Description        string   `json:"description" validate:"max=1000"`
	RuleType           string   `json:"rule_type" validate:"required,oneof=tag_match asset_group_match"`
	MatchTags          []string `json:"match_tags"`
	MatchLogic         string   `json:"match_logic" validate:"omitempty,oneof=any all"`
	MatchAssetGroupIDs []string `json:"match_asset_group_ids"`
	OwnershipType      string   `json:"ownership_type" validate:"omitempty,oneof=primary secondary stakeholder informed"`
	Priority           int      `json:"priority"`
}

// CreateScopeRule creates a new scope rule and runs initial reconciliation.
func (s *ScopeRuleService) CreateScopeRule(ctx context.Context, input CreateScopeRuleInput, createdBy string) (*accesscontrol.ScopeRule, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id", shared.ErrValidation)
	}

	// Verify group exists and is active
	grp, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: group not found", shared.ErrValidation)
	}
	if !grp.IsActive() {
		return nil, fmt.Errorf("%w: group is not active", shared.ErrValidation)
	}

	// Check max rules per group
	count, err := s.acRepo.CountScopeRules(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to count scope rules: %w", err)
	}
	if count >= int64(accesscontrol.MaxScopeRulesPerGroup) {
		return nil, fmt.Errorf("%w: maximum %d scope rules per group", shared.ErrValidation, accesscontrol.MaxScopeRulesPerGroup)
	}

	var createdByID *shared.ID
	if createdBy != "" {
		id, err := shared.IDFromString(createdBy)
		if err == nil {
			createdByID = &id
		}
	}

	ruleType := accesscontrol.ScopeRuleType(input.RuleType)
	rule, err := accesscontrol.NewScopeRule(tenantID, groupID, input.Name, ruleType, createdByID)
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		rule.UpdateDescription(input.Description)
	}
	if input.Priority != 0 {
		rule.SetPriority(input.Priority)
	}

	ownershipType := accesscontrol.OwnershipSecondary
	if input.OwnershipType != "" {
		ownershipType = accesscontrol.OwnershipType(input.OwnershipType)
	}
	if err := rule.SetOwnershipType(ownershipType); err != nil {
		return nil, err
	}

	// Set type-specific fields
	switch ruleType {
	case accesscontrol.ScopeRuleTagMatch:
		if len(input.MatchTags) == 0 {
			return nil, fmt.Errorf("%w: match_tags required for tag_match rules", shared.ErrValidation)
		}
		logic := accesscontrol.MatchLogicAny
		if input.MatchLogic == "all" {
			logic = accesscontrol.MatchLogicAll
		}
		if err := rule.SetMatchTags(input.MatchTags, logic); err != nil {
			return nil, err
		}

	case accesscontrol.ScopeRuleAssetGroupMatch:
		if len(input.MatchAssetGroupIDs) == 0 {
			return nil, fmt.Errorf("%w: match_asset_group_ids required for asset_group_match rules", shared.ErrValidation)
		}
		ids := make([]shared.ID, 0, len(input.MatchAssetGroupIDs))
		for _, idStr := range input.MatchAssetGroupIDs {
			id, err := shared.IDFromString(idStr)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid asset group id: %s", shared.ErrValidation, idStr)
			}
			ids = append(ids, id)
		}
		if err := rule.SetMatchAssetGroupIDs(ids); err != nil {
			return nil, err
		}
	}

	if err := s.acRepo.CreateScopeRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create scope rule: %w", err)
	}

	// Run initial reconciliation for this rule
	added, err := s.reconcileRule(ctx, rule)
	if err != nil {
		s.logger.Warn("initial reconciliation failed", "rule_id", rule.ID().String(), "error", err)
	} else {
		s.logger.Info("scope rule created and reconciled",
			"rule_id", rule.ID().String(),
			"name", rule.Name(),
			"assets_added", added,
		)
	}

	return rule, nil
}

// GetScopeRule retrieves a scope rule by ID with tenant isolation.
func (s *ScopeRuleService) GetScopeRule(ctx context.Context, tenantID, ruleID string) (*accesscontrol.ScopeRule, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id", shared.ErrValidation)
	}
	return s.acRepo.GetScopeRule(ctx, tid, id)
}

// UpdateScopeRuleInput represents the input for updating a scope rule.
type UpdateScopeRuleInput struct {
	Name               *string  `json:"name" validate:"omitempty,min=2,max=200"`
	Description        *string  `json:"description" validate:"omitempty,max=1000"`
	MatchTags          []string `json:"match_tags"`
	MatchLogic         *string  `json:"match_logic" validate:"omitempty,oneof=any all"`
	MatchAssetGroupIDs []string `json:"match_asset_group_ids"`
	OwnershipType      *string  `json:"ownership_type" validate:"omitempty,oneof=primary secondary stakeholder informed"`
	Priority           *int     `json:"priority"`
	IsActive           *bool    `json:"is_active"`
}

// UpdateScopeRule updates an existing scope rule.
func (s *ScopeRuleService) UpdateScopeRule(ctx context.Context, tenantID, ruleID string, input UpdateScopeRuleInput) (*accesscontrol.ScopeRule, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id", shared.ErrValidation)
	}

	rule, err := s.acRepo.GetScopeRule(ctx, tid, id)
	if err != nil {
		return nil, err
	}

	// Track if matching criteria changed (to decide if re-reconciliation needed)
	matchingChanged := false

	if input.Name != nil {
		if err := rule.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}
	if input.Description != nil {
		rule.UpdateDescription(*input.Description)
	}
	if input.Priority != nil {
		rule.SetPriority(*input.Priority)
	}
	if input.IsActive != nil {
		if *input.IsActive {
			rule.Activate()
		} else {
			rule.Deactivate()
		}
		matchingChanged = true // Activation state affects matching
	}
	if input.OwnershipType != nil {
		if err := rule.SetOwnershipType(accesscontrol.OwnershipType(*input.OwnershipType)); err != nil {
			return nil, err
		}
	}

	if input.MatchTags != nil && rule.RuleType() == accesscontrol.ScopeRuleTagMatch {
		logic := rule.MatchLogic()
		if input.MatchLogic != nil {
			logic = accesscontrol.MatchLogic(*input.MatchLogic)
		}
		if err := rule.SetMatchTags(input.MatchTags, logic); err != nil {
			return nil, err
		}
		matchingChanged = true
	} else if input.MatchLogic != nil && rule.RuleType() == accesscontrol.ScopeRuleTagMatch {
		if err := rule.SetMatchTags(rule.MatchTags(), accesscontrol.MatchLogic(*input.MatchLogic)); err != nil {
			return nil, err
		}
		matchingChanged = true
	}

	if input.MatchAssetGroupIDs != nil && rule.RuleType() == accesscontrol.ScopeRuleAssetGroupMatch {
		ids := make([]shared.ID, 0, len(input.MatchAssetGroupIDs))
		for _, idStr := range input.MatchAssetGroupIDs {
			agID, err := shared.IDFromString(idStr)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid asset group id: %s", shared.ErrValidation, idStr)
			}
			ids = append(ids, agID)
		}
		if err := rule.SetMatchAssetGroupIDs(ids); err != nil {
			return nil, err
		}
		matchingChanged = true
	}

	if err := s.acRepo.UpdateScopeRule(ctx, tid, rule); err != nil {
		return nil, fmt.Errorf("failed to update scope rule: %w", err)
	}

	// Only re-reconcile if matching criteria changed and rule is active
	if matchingChanged && rule.IsActive() {
		added, err := s.reconcileRule(ctx, rule)
		if err != nil {
			s.logger.Warn("reconciliation after update failed", "rule_id", rule.ID().String(), "error", err)
		} else if added > 0 {
			s.logger.Info("scope rule updated and reconciled", "rule_id", ruleID, "assets_added", added)
		}
	}

	return rule, nil
}

// DeleteScopeRule deletes a scope rule and removes its auto-assignments.
func (s *ScopeRuleService) DeleteScopeRule(ctx context.Context, tenantID, ruleID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return fmt.Errorf("%w: invalid rule id", shared.ErrValidation)
	}

	rule, err := s.acRepo.GetScopeRule(ctx, tid, id)
	if err != nil {
		return err
	}

	// Remove auto-assigned assets first
	removed, err := s.acRepo.DeleteAutoAssignedByRule(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to clean up auto-assigned assets: %w", err)
	}

	if err := s.acRepo.DeleteScopeRule(ctx, tid, id); err != nil {
		return err
	}

	// Refresh access for affected assets (single full refresh instead of per-asset)
	if removed > 0 {
		if err := s.acRepo.RefreshUserAccessibleAssets(ctx); err != nil {
			s.logger.Warn("failed to refresh access after rule deletion", "error", err)
		}
	}

	s.logger.Info("scope rule deleted", "rule_id", ruleID, "name", rule.Name(), "assets_removed", removed)
	return nil
}

// ListScopeRules lists scope rules for a group.
func (s *ScopeRuleService) ListScopeRules(ctx context.Context, groupID string, filter accesscontrol.ScopeRuleFilter) ([]*accesscontrol.ScopeRule, error) {
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id", shared.ErrValidation)
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	return s.acRepo.ListScopeRules(ctx, gid, filter)
}

// PreviewScopeRuleResult shows what assets would be affected by a rule.
type PreviewScopeRuleResult struct {
	RuleID          string `json:"rule_id"`
	RuleName        string `json:"rule_name"`
	MatchingAssets  int    `json:"matching_assets"`
	AlreadyAssigned int    `json:"already_assigned"`
	WouldAdd        int    `json:"would_add"`
}

// PreviewScopeRule shows what assets would match a rule without applying changes.
func (s *ScopeRuleService) PreviewScopeRule(ctx context.Context, tenantID, ruleID string) (*PreviewScopeRuleResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id", shared.ErrValidation)
	}

	rule, err := s.acRepo.GetScopeRule(ctx, tid, id)
	if err != nil {
		return nil, err
	}

	matchingAssetIDs, err := s.findMatchingAssets(ctx, rule)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching assets: %w", err)
	}

	// Check which are already assigned
	existingAssetIDs, err := s.acRepo.ListAssetsByGroup(ctx, rule.GroupID())
	if err != nil {
		return nil, fmt.Errorf("failed to list existing assets: %w", err)
	}
	existingSet := make(map[shared.ID]struct{}, len(existingAssetIDs))
	for _, id := range existingAssetIDs {
		existingSet[id] = struct{}{}
	}

	alreadyAssigned := 0
	for _, assetID := range matchingAssetIDs {
		if _, exists := existingSet[assetID]; exists {
			alreadyAssigned++
		}
	}

	return &PreviewScopeRuleResult{
		RuleID:          rule.ID().String(),
		RuleName:        rule.Name(),
		MatchingAssets:  len(matchingAssetIDs),
		AlreadyAssigned: alreadyAssigned,
		WouldAdd:        len(matchingAssetIDs) - alreadyAssigned,
	}, nil
}

// ReconcileGroupResult shows the result of a reconciliation run.
type ReconcileGroupResult struct {
	RulesEvaluated int `json:"rules_evaluated"`
	AssetsAdded    int `json:"assets_added"`
	AssetsRemoved  int `json:"assets_removed"`
}

// ReconcileGroup re-evaluates all active scope rules for a group.
func (s *ScopeRuleService) ReconcileGroup(ctx context.Context, groupID string) (*ReconcileGroupResult, error) {
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id", shared.ErrValidation)
	}

	rules, err := s.acRepo.ListActiveScopeRulesByGroup(ctx, gid)
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope rules: %w", err)
	}

	result := &ReconcileGroupResult{RulesEvaluated: len(rules)}

	for _, rule := range rules {
		added, err := s.reconcileRule(ctx, rule)
		if err != nil {
			s.logger.Warn("reconciliation failed for rule", "rule_id", rule.ID().String(), "error", err)
			continue
		}
		result.AssetsAdded += added
	}

	s.logger.Info("group reconciliation complete",
		"group_id", groupID,
		"rules_evaluated", result.RulesEvaluated,
		"assets_added", result.AssetsAdded,
	)

	return result, nil
}

// EvaluateAsset evaluates all active scope rules in a tenant against a single asset.
// Called when an asset is created or its tags change.
func (s *ScopeRuleService) EvaluateAsset(ctx context.Context, tenantID shared.ID, assetID shared.ID, tags []string, assetGroupIDs []shared.ID) error {
	rules, err := s.acRepo.ListActiveScopeRulesByTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to list active scope rules: %w", err)
	}

	if len(rules) == 0 {
		return nil
	}

	// Collect all matched assignments, then batch insert + single refresh
	type matchedAssignment struct {
		ao   *accesscontrol.AssetOwner
		rule *accesscontrol.ScopeRule
	}
	var matched []matchedAssignment

	for _, rule := range rules {
		isMatch := false

		switch rule.RuleType() {
		case accesscontrol.ScopeRuleTagMatch:
			isMatch = matchTags(tags, rule.MatchTags(), rule.MatchLogic())
		case accesscontrol.ScopeRuleAssetGroupMatch:
			isMatch = matchAssetGroups(assetGroupIDs, rule.MatchAssetGroupIDs())
		}

		if isMatch {
			ao, err := accesscontrol.NewAssetOwnerForGroup(assetID, rule.GroupID(), rule.OwnershipType(), nil)
			if err != nil {
				s.logger.Warn("failed to create asset owner", "error", err)
				continue
			}
			matched = append(matched, matchedAssignment{ao: ao, rule: rule})
		}
	}

	if len(matched) == 0 {
		return nil
	}

	// Group by rule for source tracking - each rule needs its own bulk insert
	ruleOwners := make(map[shared.ID][]*accesscontrol.AssetOwner)
	for _, m := range matched {
		ruleOwners[m.rule.ID()] = append(ruleOwners[m.rule.ID()], m.ao)
	}

	totalAdded := 0
	for rID, aos := range ruleOwners {
		rid := rID
		added, err := s.acRepo.BulkCreateAssetOwnersWithSource(ctx, aos, "scope_rule", &rid)
		if err != nil {
			s.logger.Warn("failed to bulk auto-assign asset", "rule_id", rid.String(), "error", err)
			continue
		}
		totalAdded += added
	}

	// Single refresh call after all assignments (instead of per-assignment)
	if totalAdded > 0 {
		if err := s.acRepo.RefreshUserAccessibleAssets(ctx); err != nil {
			s.logger.Warn("failed to refresh access after asset evaluation", "error", err)
		}
	}

	return nil
}

// reconcileRule applies a single rule to find and assign matching assets.
// Uses batch insert + single refresh instead of per-asset queries.
func (s *ScopeRuleService) reconcileRule(ctx context.Context, rule *accesscontrol.ScopeRule) (int, error) {
	matchingAssetIDs, err := s.findMatchingAssets(ctx, rule)
	if err != nil {
		return 0, err
	}

	if len(matchingAssetIDs) == 0 {
		return 0, nil
	}

	// Get already-assigned assets for this group
	existingAssetIDs, err := s.acRepo.ListAssetsByGroup(ctx, rule.GroupID())
	if err != nil {
		return 0, fmt.Errorf("failed to list existing assets: %w", err)
	}
	existingSet := make(map[shared.ID]struct{}, len(existingAssetIDs))
	for _, id := range existingAssetIDs {
		existingSet[id] = struct{}{}
	}

	// Collect new assets to assign
	owners := make([]*accesscontrol.AssetOwner, 0, len(matchingAssetIDs))
	for _, assetID := range matchingAssetIDs {
		if _, exists := existingSet[assetID]; exists {
			continue // Already assigned
		}
		ao, err := accesscontrol.NewAssetOwnerForGroup(assetID, rule.GroupID(), rule.OwnershipType(), nil)
		if err != nil {
			continue
		}
		owners = append(owners, ao)
	}

	if len(owners) == 0 {
		return 0, nil
	}

	// Batch insert all new assignments (1 query instead of N)
	ruleID := rule.ID()
	added, err := s.acRepo.BulkCreateAssetOwnersWithSource(ctx, owners, "scope_rule", &ruleID)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk assign assets: %w", err)
	}

	// Single refresh call after all inserts (1 query instead of N)
	if added > 0 {
		if err := s.acRepo.RefreshUserAccessibleAssets(ctx); err != nil {
			s.logger.Warn("failed to refresh access after reconciliation", "error", err)
		}
	}

	return added, nil
}

// findMatchingAssets returns asset IDs that match a rule's criteria.
func (s *ScopeRuleService) findMatchingAssets(ctx context.Context, rule *accesscontrol.ScopeRule) ([]shared.ID, error) {
	switch rule.RuleType() {
	case accesscontrol.ScopeRuleTagMatch:
		return s.acRepo.FindAssetsByTagMatch(ctx, rule.TenantID(), rule.MatchTags(), rule.MatchLogic())
	case accesscontrol.ScopeRuleAssetGroupMatch:
		return s.acRepo.FindAssetsByAssetGroupMatch(ctx, rule.TenantID(), rule.MatchAssetGroupIDs())
	default:
		return nil, fmt.Errorf("%w: unknown rule type: %s", shared.ErrValidation, rule.RuleType())
	}
}

// matchTags checks if asset tags match rule tags based on logic.
func matchTags(assetTags, ruleTags []string, logic accesscontrol.MatchLogic) bool {
	if len(ruleTags) == 0 {
		return false
	}
	tagSet := make(map[string]struct{}, len(assetTags))
	for _, t := range assetTags {
		tagSet[t] = struct{}{}
	}

	if logic == accesscontrol.MatchLogicAll {
		for _, t := range ruleTags {
			if _, ok := tagSet[t]; !ok {
				return false
			}
		}
		return true
	}

	// MatchLogicAny
	for _, t := range ruleTags {
		if _, ok := tagSet[t]; ok {
			return true
		}
	}
	return false
}

// matchAssetGroups checks if asset belongs to any of the rule's asset groups.
func matchAssetGroups(assetGroupIDs, ruleGroupIDs []shared.ID) bool {
	set := make(map[shared.ID]struct{}, len(assetGroupIDs))
	for _, id := range assetGroupIDs {
		set[id] = struct{}{}
	}
	for _, id := range ruleGroupIDs {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}
