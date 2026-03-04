package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// AssignmentRule represents a rule for automated finding-to-group assignment.
// This mirrors the assignment_rules database table.
type AssignmentRule struct {
	ID            shared.ID
	TenantID      shared.ID
	Name          string
	Description   string
	Priority      int
	IsActive      bool
	Conditions    []RuleCondition
	TargetGroupID shared.ID
	Options       map[string]any
}

// RuleCondition represents a single condition within an assignment rule.
// Conditions are stored as a JSONB array in the database.
type RuleCondition struct {
	Type  string `json:"type"`  // "severity", "tool_name", "finding_type", "source", "tag"
	Op    string `json:"op"`    // "eq", "neq", "in", "contains"
	Value string `json:"value"` // The value to match against
}

// AssignmentRuleRepository defines the interface for querying assignment rules.
type AssignmentRuleRepository interface {
	// ListActiveByTenant returns all active assignment rules for a tenant, ordered by priority descending.
	ListActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*AssignmentRule, error)
}

// AssignmentEngine evaluates assignment rules against findings
// and returns the list of group IDs that should be assigned.
type AssignmentEngine struct {
	ruleRepo AssignmentRuleRepository
	logger   *logger.Logger
}

// NewAssignmentEngine creates a new AssignmentEngine.
func NewAssignmentEngine(ruleRepo AssignmentRuleRepository, log *logger.Logger) *AssignmentEngine {
	return &AssignmentEngine{
		ruleRepo: ruleRepo,
		logger:   log.With("service", "assignment-engine"),
	}
}

// EvaluateRules evaluates all active assignment rules for a tenant against a finding.
// It returns the list of group IDs whose rules matched.
// Rules are evaluated in priority order (highest first). All matching rules contribute
// their target group ID to the result set (no short-circuiting).
func (e *AssignmentEngine) EvaluateRules(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) ([]shared.ID, error) {
	if finding == nil {
		return nil, fmt.Errorf("%w: finding is required", shared.ErrValidation)
	}

	rules, err := e.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignment rules: %w", err)
	}

	if len(rules) == 0 {
		return nil, nil
	}

	// Track unique group IDs to avoid duplicates
	seen := make(map[shared.ID]struct{})
	result := make([]shared.ID, 0, len(rules))

	for _, rule := range rules {
		if e.matchesAllConditions(rule.Conditions, finding) {
			if _, exists := seen[rule.TargetGroupID]; !exists {
				seen[rule.TargetGroupID] = struct{}{}
				result = append(result, rule.TargetGroupID)
				e.logger.Debug("assignment rule matched",
					"rule_id", rule.ID.String(),
					"rule_name", rule.Name,
					"group_id", rule.TargetGroupID.String(),
					"finding_severity", finding.Severity().String(),
					"finding_tool", finding.ToolName(),
				)
			}
		}
	}

	e.logger.Info("assignment rules evaluated",
		"tenant_id", tenantID.String(),
		"total_rules", len(rules),
		"matched_groups", len(result),
	)

	return result, nil
}

// matchesAllConditions checks if a finding matches ALL conditions of a rule.
// An empty conditions list means the rule always matches.
func (e *AssignmentEngine) matchesAllConditions(conditions []RuleCondition, finding *vulnerability.Finding) bool {
	for _, cond := range conditions {
		if !e.matchesCondition(cond, finding) {
			return false
		}
	}
	return true
}

// matchesCondition evaluates a single condition against a finding.
func (e *AssignmentEngine) matchesCondition(cond RuleCondition, finding *vulnerability.Finding) bool {
	fieldValue := e.extractFieldValue(cond.Type, finding)

	switch cond.Op {
	case "eq":
		return strings.EqualFold(fieldValue, cond.Value)
	case "neq":
		return !strings.EqualFold(fieldValue, cond.Value)
	case "in":
		return e.valueInList(fieldValue, cond.Value)
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(cond.Value))
	default:
		// Unknown operator defaults to equality
		return strings.EqualFold(fieldValue, cond.Value)
	}
}

// extractFieldValue extracts the field value from a finding based on condition type.
func (e *AssignmentEngine) extractFieldValue(condType string, finding *vulnerability.Finding) string {
	switch condType {
	case "severity":
		return finding.Severity().String()
	case "tool_name":
		return finding.ToolName()
	case "finding_type":
		return finding.FindingType().String()
	case "source":
		return finding.Source().String()
	case "tag":
		// Tags are joined for matching purposes
		return strings.Join(finding.Tags(), ",")
	default:
		return ""
	}
}

// valueInList checks if value is in a comma-separated list (case-insensitive).
func (e *AssignmentEngine) valueInList(value, commaSeparatedList string) bool {
	items := strings.Split(commaSeparatedList, ",")
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

// ParseConditions parses a JSON-encoded conditions array into RuleCondition slice.
func ParseConditions(data []byte) ([]RuleCondition, error) {
	var conditions []RuleCondition
	if err := json.Unmarshal(data, &conditions); err != nil {
		return nil, fmt.Errorf("failed to parse conditions: %w", err)
	}
	return conditions, nil
}
