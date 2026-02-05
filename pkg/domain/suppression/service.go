package suppression

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Service provides business logic for suppression rules.
type Service struct {
	repo Repository
	log  *logger.Logger
}

// NewService creates a new suppression service.
func NewService(repo Repository, log *logger.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// CreateRuleInput contains input for creating a suppression rule.
type CreateRuleInput struct {
	TenantID        shared.ID
	Name            string
	Description     string
	SuppressionType SuppressionType
	RuleID          string     // Tool rule ID pattern
	ToolName        string     // Tool name filter
	PathPattern     string     // File path pattern
	AssetID         *shared.ID // Optional asset filter
	RequestedBy     shared.ID
	ExpiresAt       *string // ISO8601 format
}

// CreateRule creates a new suppression rule.
func (s *Service) CreateRule(ctx context.Context, input CreateRuleInput) (*Rule, error) {
	rule, err := NewRule(
		input.TenantID,
		input.Name,
		input.SuppressionType,
		input.RequestedBy,
	)
	if err != nil {
		return nil, err
	}

	// Set criteria
	rule.SetRuleIDPattern(input.RuleID)
	rule.SetToolName(input.ToolName)
	rule.SetPathPattern(input.PathPattern)
	rule.SetAssetID(input.AssetID)
	rule.SetDescription(input.Description)

	// Validate criteria
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	// Parse and set expiration if provided
	if input.ExpiresAt != nil && *input.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expires_at format (expected RFC3339)", shared.ErrValidation)
		}
		rule.SetExpiresAt(&expiresAt)
	}

	// Save
	if err := s.repo.Save(ctx, rule); err != nil {
		return nil, err
	}

	// Record audit
	_ = s.repo.RecordAudit(ctx, rule.ID(), "created", &input.RequestedBy, map[string]any{
		"name":             input.Name,
		"suppression_type": string(input.SuppressionType),
		"rule_id":          input.RuleID,
		"tool_name":        input.ToolName,
		"path_pattern":     input.PathPattern,
	})

	return rule, nil
}

// ApproveRuleInput contains input for approving a rule.
type ApproveRuleInput struct {
	TenantID   shared.ID
	RuleID     shared.ID
	ApprovedBy shared.ID
}

// ApproveRule approves a pending suppression rule.
func (s *Service) ApproveRule(ctx context.Context, input ApproveRuleInput) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	if err := rule.Approve(input.ApprovedBy); err != nil {
		return nil, err
	}

	if err := s.repo.Save(ctx, rule); err != nil {
		return nil, err
	}

	// Record audit
	_ = s.repo.RecordAudit(ctx, rule.ID(), "approved", &input.ApprovedBy, nil)

	return rule, nil
}

// RejectRuleInput contains input for rejecting a rule.
type RejectRuleInput struct {
	TenantID   shared.ID
	RuleID     shared.ID
	RejectedBy shared.ID
	Reason     string
}

// RejectRule rejects a pending suppression rule.
func (s *Service) RejectRule(ctx context.Context, input RejectRuleInput) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	if err := rule.Reject(input.RejectedBy, input.Reason); err != nil {
		return nil, err
	}

	if err := s.repo.Save(ctx, rule); err != nil {
		return nil, err
	}

	// Record audit
	_ = s.repo.RecordAudit(ctx, rule.ID(), "rejected", &input.RejectedBy, map[string]any{
		"reason": input.Reason,
	})

	return rule, nil
}

// UpdateRuleInput contains input for updating a suppression rule.
type UpdateRuleInput struct {
	TenantID    shared.ID
	RuleID      shared.ID
	Name        *string
	Description *string
	RuleIDPat   *string // Rule ID pattern
	ToolName    *string
	PathPattern *string
	ExpiresAt   *string // ISO8601 format, empty string to clear
	UpdatedBy   shared.ID
}

// UpdateRule updates an existing suppression rule.
// Only pending rules can be updated.
func (s *Service) UpdateRule(ctx context.Context, input UpdateRuleInput) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	// Only pending rules can be updated
	if rule.Status() != RuleStatusPending {
		return nil, ErrRuleNotPending
	}

	changes := make(map[string]any)

	if input.Name != nil {
		rule.SetName(*input.Name)
		changes["name"] = *input.Name
	}
	if input.Description != nil {
		rule.SetDescription(*input.Description)
		changes["description"] = *input.Description
	}
	if input.RuleIDPat != nil {
		rule.SetRuleIDPattern(*input.RuleIDPat)
		changes["rule_id"] = *input.RuleIDPat
	}
	if input.ToolName != nil {
		rule.SetToolName(*input.ToolName)
		changes["tool_name"] = *input.ToolName
	}
	if input.PathPattern != nil {
		rule.SetPathPattern(*input.PathPattern)
		changes["path_pattern"] = *input.PathPattern
	}
	if input.ExpiresAt != nil {
		if *input.ExpiresAt == "" {
			rule.SetExpiresAt(nil)
			changes["expires_at"] = nil
		} else {
			expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid expires_at format (expected RFC3339)", shared.ErrValidation)
			}
			rule.SetExpiresAt(&expiresAt)
			changes["expires_at"] = *input.ExpiresAt
		}
	}

	// Validate after changes
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	if err := s.repo.Save(ctx, rule); err != nil {
		return nil, err
	}

	// Record audit
	_ = s.repo.RecordAudit(ctx, rule.ID(), "updated", &input.UpdatedBy, changes)

	return rule, nil
}

// GetRule retrieves a suppression rule by ID.
func (s *Service) GetRule(ctx context.Context, tenantID, ruleID shared.ID) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, tenantID, ruleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}
	return rule, nil
}

// ListRules lists suppression rules for a tenant.
func (s *Service) ListRules(ctx context.Context, tenantID shared.ID, filter RuleFilter) ([]*Rule, error) {
	return s.repo.FindByTenant(ctx, tenantID, filter)
}

// ListActiveRules lists all active (approved, not expired) rules.
func (s *Service) ListActiveRules(ctx context.Context, tenantID shared.ID) ([]*Rule, error) {
	return s.repo.FindActiveByTenant(ctx, tenantID)
}

// ListPendingRules lists all pending rules awaiting approval.
func (s *Service) ListPendingRules(ctx context.Context, tenantID shared.ID) ([]*Rule, error) {
	return s.repo.FindPendingByTenant(ctx, tenantID)
}

// DeleteRule deletes a suppression rule.
func (s *Service) DeleteRule(ctx context.Context, tenantID, ruleID, deletedBy shared.ID) error {
	rule, err := s.repo.FindByID(ctx, tenantID, ruleID)
	if err != nil {
		return err
	}
	if rule == nil {
		return ErrRuleNotFound
	}

	// Record audit before deletion
	_ = s.repo.RecordAudit(ctx, ruleID, "deleted", &deletedBy, map[string]any{
		"name":   rule.Name(),
		"status": string(rule.Status()),
	})

	return s.repo.Delete(ctx, tenantID, ruleID)
}

// CheckSuppression checks if a finding matches any active suppression rules.
func (s *Service) CheckSuppression(ctx context.Context, tenantID shared.ID, match FindingMatch) ([]*Rule, error) {
	return s.repo.FindMatchingRules(ctx, tenantID, match)
}

// ApplySuppression applies a suppression rule to a finding.
func (s *Service) ApplySuppression(ctx context.Context, findingID, ruleID shared.ID) error {
	return s.repo.RecordSuppression(ctx, findingID, ruleID, "system")
}

// ExpireRules expires all rules past their expiration date.
func (s *Service) ExpireRules(ctx context.Context) (int64, error) {
	return s.repo.ExpireRules(ctx)
}
