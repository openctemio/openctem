package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AssignmentRuleService handles assignment rule business operations.
type AssignmentRuleService struct {
	acRepo    accesscontrol.Repository
	groupRepo group.Repository
	logger    *logger.Logger
}

// NewAssignmentRuleService creates a new AssignmentRuleService.
func NewAssignmentRuleService(
	acRepo accesscontrol.Repository,
	groupRepo group.Repository,
	log *logger.Logger,
) *AssignmentRuleService {
	return &AssignmentRuleService{
		acRepo:    acRepo,
		groupRepo: groupRepo,
		logger:    log.With("service", "assignment_rule"),
	}
}

// CreateRuleInput represents the input for creating an assignment rule.
type CreateRuleInput struct {
	TenantID      string                            `json:"-"`
	Name          string                            `json:"name" validate:"required,min=2,max=200"`
	Description   string                            `json:"description" validate:"max=1000"`
	Priority      int                               `json:"priority"`
	Conditions    accesscontrol.AssignmentConditions `json:"conditions"`
	TargetGroupID string                            `json:"target_group_id" validate:"required,uuid"`
	Options       accesscontrol.AssignmentOptions   `json:"options"`
}

// CreateRule creates a new assignment rule.
func (s *AssignmentRuleService) CreateRule(ctx context.Context, input CreateRuleInput, createdBy string) (*accesscontrol.AssignmentRule, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	targetGroupID, err := shared.IDFromString(input.TargetGroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid target group id format", shared.ErrValidation)
	}

	// Verify target group exists
	targetGroup, err := s.groupRepo.GetByID(ctx, targetGroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: target group not found", shared.ErrValidation)
	}
	if !targetGroup.IsActive() {
		return nil, accesscontrol.ErrTargetGroupInactive
	}

	var createdByID *shared.ID
	if createdBy != "" {
		id, err := shared.IDFromString(createdBy)
		if err == nil {
			createdByID = &id
		}
	}

	rule, err := accesscontrol.NewAssignmentRule(tenantID, input.Name, input.Conditions, targetGroupID, createdByID)
	if err != nil {
		return nil, err
	}

	if input.Description != "" {
		rule.UpdateDescription(input.Description)
	}
	if input.Priority != 0 {
		rule.UpdatePriority(input.Priority)
	}
	if input.Options != (accesscontrol.AssignmentOptions{}) {
		rule.UpdateOptions(input.Options)
	}

	if err := s.acRepo.CreateAssignmentRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create assignment rule: %w", err)
	}

	s.logger.Info("assignment rule created", "id", rule.ID().String(), "name", rule.Name())
	return rule, nil
}

// GetRule retrieves an assignment rule by ID.
func (s *AssignmentRuleService) GetRule(ctx context.Context, ruleID string) (*accesscontrol.AssignmentRule, error) {
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id format", shared.ErrValidation)
	}

	return s.acRepo.GetAssignmentRule(ctx, id)
}

// UpdateRuleInput represents the input for updating an assignment rule.
type UpdateRuleInput struct {
	Name          *string                            `json:"name" validate:"omitempty,min=2,max=200"`
	Description   *string                            `json:"description" validate:"omitempty,max=1000"`
	Priority      *int                               `json:"priority"`
	IsActive      *bool                              `json:"is_active"`
	Conditions    *accesscontrol.AssignmentConditions `json:"conditions"`
	TargetGroupID *string                            `json:"target_group_id" validate:"omitempty,uuid"`
	Options       *accesscontrol.AssignmentOptions   `json:"options"`
}

// UpdateRule updates an existing assignment rule.
func (s *AssignmentRuleService) UpdateRule(ctx context.Context, ruleID string, input UpdateRuleInput) (*accesscontrol.AssignmentRule, error) {
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id format", shared.ErrValidation)
	}

	rule, err := s.acRepo.GetAssignmentRule(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		if err := rule.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		rule.UpdateDescription(*input.Description)
	}

	if input.Priority != nil {
		rule.UpdatePriority(*input.Priority)
	}

	if input.IsActive != nil {
		if *input.IsActive {
			rule.Activate()
		} else {
			rule.Deactivate()
		}
	}

	if input.Conditions != nil {
		rule.UpdateConditions(*input.Conditions)
	}

	if input.TargetGroupID != nil {
		targetGroupID, err := shared.IDFromString(*input.TargetGroupID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid target group id format", shared.ErrValidation)
		}
		// Verify target group exists
		targetGroup, err := s.groupRepo.GetByID(ctx, targetGroupID)
		if err != nil {
			return nil, fmt.Errorf("%w: target group not found", shared.ErrValidation)
		}
		if !targetGroup.IsActive() {
			return nil, accesscontrol.ErrTargetGroupInactive
		}
		if err := rule.UpdateTargetGroup(targetGroupID); err != nil {
			return nil, err
		}
	}

	if input.Options != nil {
		rule.UpdateOptions(*input.Options)
	}

	if err := s.acRepo.UpdateAssignmentRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to update assignment rule: %w", err)
	}

	s.logger.Info("assignment rule updated", "id", ruleID)
	return rule, nil
}

// DeleteRule deletes an assignment rule.
func (s *AssignmentRuleService) DeleteRule(ctx context.Context, ruleID string) error {
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return fmt.Errorf("%w: invalid rule id format", shared.ErrValidation)
	}

	if err := s.acRepo.DeleteAssignmentRule(ctx, id); err != nil {
		return err
	}

	s.logger.Info("assignment rule deleted", "id", ruleID)
	return nil
}

// ListAssignmentRulesInput represents the input for listing assignment rules.
type ListAssignmentRulesInput struct {
	TenantID      string
	IsActive      *bool
	TargetGroupID *string
	Search        string
	Limit         int
	Offset        int
	OrderBy       string
	OrderDesc     bool
}

// ListAssignmentRulesOutput represents the output for listing assignment rules.
type ListAssignmentRulesOutput struct {
	Rules      []*accesscontrol.AssignmentRule
	TotalCount int64
}

// ListRules lists assignment rules with filtering.
func (s *AssignmentRuleService) ListRules(ctx context.Context, input ListAssignmentRulesInput) (*ListAssignmentRulesOutput, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	filter := accesscontrol.AssignmentRuleFilter{
		IsActive:  input.IsActive,
		Search:    input.Search,
		Limit:     input.Limit,
		Offset:    input.Offset,
		OrderBy:   input.OrderBy,
		OrderDesc: input.OrderDesc,
	}

	if input.TargetGroupID != nil {
		gid, err := shared.IDFromString(*input.TargetGroupID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid target group id format", shared.ErrValidation)
		}
		filter.TargetGroupID = &gid
	}

	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	rules, err := s.acRepo.ListAssignmentRules(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignment rules: %w", err)
	}

	count, err := s.acRepo.CountAssignmentRules(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count assignment rules: %w", err)
	}

	return &ListAssignmentRulesOutput{
		Rules:      rules,
		TotalCount: count,
	}, nil
}

// TestRuleResult represents assets that match a rule's conditions.
type TestRuleResult struct {
	RuleID         string   `json:"rule_id"`
	RuleName       string   `json:"rule_name"`
	MatchingAssets int      `json:"matching_assets"`
	TargetGroupID  string   `json:"target_group_id"`
	Message        string   `json:"message"`
}

// TestRule evaluates a rule against existing data (dry run).
func (s *AssignmentRuleService) TestRule(ctx context.Context, ruleID string) (*TestRuleResult, error) {
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id format", shared.ErrValidation)
	}

	rule, err := s.acRepo.GetAssignmentRule(ctx, id)
	if err != nil {
		return nil, err
	}

	// For now, return rule info without full asset matching.
	// Full matching requires querying assets by conditions which is complex.
	// This endpoint lets users verify the rule is correctly configured.
	return &TestRuleResult{
		RuleID:         rule.ID().String(),
		RuleName:       rule.Name(),
		MatchingAssets: 0,
		TargetGroupID:  rule.TargetGroupID().String(),
		Message:        "Rule configuration is valid. Full asset matching will be available in a future release.",
	}, nil
}
