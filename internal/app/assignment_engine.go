package app

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// AssignmentResult represents a single rule match with its target group and options.
type AssignmentResult struct {
	GroupID shared.ID
	RuleID  shared.ID
	Options accesscontrol.AssignmentOptions
}

// AssignmentEngine evaluates assignment rules against findings
// and returns the list of matching groups with their options.
type AssignmentEngine struct {
	acRepo accesscontrol.Repository
	logger *logger.Logger
}

// NewAssignmentEngine creates a new AssignmentEngine.
func NewAssignmentEngine(acRepo accesscontrol.Repository, log *logger.Logger) *AssignmentEngine {
	return &AssignmentEngine{
		acRepo: acRepo,
		logger: log.With("service", "assignment-engine"),
	}
}

// EvaluateRules evaluates all active assignment rules for a tenant against a finding.
// Rules are evaluated in priority order (highest first). All matching rules contribute
// their target group to the result set (no short-circuiting).
func (e *AssignmentEngine) EvaluateRules(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) ([]AssignmentResult, error) {
	if finding == nil {
		return nil, fmt.Errorf("%w: finding is required", shared.ErrValidation)
	}

	rules, err := e.acRepo.ListActiveRulesByPriority(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignment rules: %w", err)
	}

	if len(rules) == 0 {
		return nil, nil
	}

	seen := make(map[shared.ID]struct{})
	results := make([]AssignmentResult, 0, len(rules))

	for _, rule := range rules {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if e.MatchesConditions(rule.Conditions(), finding) {
			gid := rule.TargetGroupID()
			if _, exists := seen[gid]; !exists {
				seen[gid] = struct{}{}
				results = append(results, AssignmentResult{
					GroupID: gid,
					RuleID:  rule.ID(),
					Options: rule.Options(),
				})
				e.logger.Debug("assignment rule matched",
					"rule_id", rule.ID().String(),
					"rule_name", rule.Name(),
					"group_id", gid.String(),
					"finding_id", finding.ID().String(),
				)
			}
		}
	}

	e.logger.Info("assignment rules evaluated",
		"tenant_id", tenantID.String(),
		"total_rules", len(rules),
		"matched_groups", len(results),
	)

	return results, nil
}

// MatchesConditions checks if a finding matches the given conditions.
// All non-empty condition fields must match (AND logic).
// Empty conditions = catch-all (always matches).
// assetType is optional — pass the asset's type when available for AssetTypes condition evaluation.
func (e *AssignmentEngine) MatchesConditions(conds accesscontrol.AssignmentConditions, finding *vulnerability.Finding, assetType ...string) bool {
	if finding == nil {
		return false
	}
	if len(conds.FindingSeverity) > 0 {
		if !stringInSliceFold(finding.Severity().String(), conds.FindingSeverity) {
			return false
		}
	}

	if len(conds.FindingSource) > 0 {
		if !stringInSliceFold(finding.Source().String(), conds.FindingSource) {
			return false
		}
	}

	if len(conds.FindingType) > 0 {
		if !stringInSliceFold(finding.FindingType().String(), conds.FindingType) {
			return false
		}
	}

	if len(conds.AssetTags) > 0 {
		if !hasAnyTag(finding.Tags(), conds.AssetTags) {
			return false
		}
	}

	if conds.FilePathPattern != "" {
		if !matchesFilePathPattern(finding.FilePath(), conds.FilePathPattern) {
			return false
		}
	}

	if len(conds.AssetTypes) > 0 {
		at := ""
		if len(assetType) > 0 {
			at = assetType[0]
		}
		if at == "" {
			// No asset type available — cannot match this condition
			return false
		}
		if !stringInSliceFold(at, conds.AssetTypes) {
			return false
		}
	}

	return true
}

// stringInSliceFold checks if value is in slice (case-insensitive).
func stringInSliceFold(value string, slice []string) bool {
	for _, s := range slice {
		if strings.EqualFold(value, s) {
			return true
		}
	}
	return false
}

// hasAnyTag checks if any of the finding's tags match any of the required tags.
func hasAnyTag(findingTags, requiredTags []string) bool {
	required := make(map[string]struct{}, len(requiredTags))
	for _, rt := range requiredTags {
		required[strings.ToLower(rt)] = struct{}{}
	}
	for _, ft := range findingTags {
		if _, ok := required[strings.ToLower(ft)]; ok {
			return true
		}
	}
	return false
}

// matchesFilePathPattern matches a file path against a glob pattern.
func matchesFilePathPattern(filePath, pattern string) bool {
	if filePath == "" {
		return false
	}
	matched, err := path.Match(pattern, filePath)
	if err != nil {
		return false
	}
	return matched
}
