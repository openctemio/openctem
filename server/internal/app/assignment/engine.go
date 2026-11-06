// Package assignment implements the application service for the assignment bounded context — orchestrates pkg/domain/assignment entities and cross-cutting concerns (audit, notifications, RBAC).
package assignment

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Result represents a single rule match with its target group and options.
type Result struct {
	GroupID shared.ID
	RuleID  shared.ID
	Options accesscontrol.AssignmentOptions
}

// AssetFacts is what a rule may read about the finding's asset: its stored
// (type, sub_type) and its tags (the asset's own, never the finding's).
type AssetFacts struct {
	Type asset.TypeRef
	Tags []string
}

// AssetFactsResolver returns the facts of a finding's asset, so rules scoped
// by AssetTypes or AssetTags can be evaluated. Optional: when unset, rules
// with an asset condition cannot match; wiring it makes those rules work.
type AssetFactsResolver func(ctx context.Context, tenantID, assetID shared.ID) (AssetFacts, error)

// Engine evaluates assignment rules against findings
// and returns the list of matching groups with their options.
type Engine struct {
	acRepo   accesscontrol.Repository
	assetFor AssetFactsResolver
	logger   *logger.Logger
}

// NewEngine creates a new Engine.
func NewEngine(acRepo accesscontrol.Repository, log *logger.Logger) *Engine {
	return &Engine{
		acRepo: acRepo,
		logger: log.With("service", "assignment-engine"),
	}
}

// SetAssetFactsResolver wires the resolver used to evaluate AssetTypes and
// AssetTags conditions. Without it, rules that filter by either never match
// (they need the asset).
func (e *Engine) SetAssetFactsResolver(r AssetFactsResolver) { e.assetFor = r }

// rulesNeedAsset reports whether any rule filters by asset type or asset tags,
// so we only pay for the asset lookup when it can affect the outcome.
func rulesNeedAsset(rules []*accesscontrol.AssignmentRule) bool {
	for _, r := range rules {
		c := r.Conditions()
		if len(c.AssetTypes) > 0 || len(c.AssetTags) > 0 {
			return true
		}
	}
	return false
}

// EvaluateRules evaluates all active assignment rules for a tenant against a finding.
// Rules are evaluated in priority order (highest first). All matching rules contribute
// their target group to the result set (no short-circuiting).
func (e *Engine) EvaluateRules(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) ([]Result, error) {
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

	needAsset := e.assetFor != nil && rulesNeedAsset(rules)
	results := e.matchRules(ctx, tenantID, finding, rules, needAsset)

	e.logger.Info("assignment rules evaluated",
		"tenant_id", tenantID.String(),
		"total_rules", len(rules),
		"matched_groups", len(results),
	)

	return results, nil
}

// EvaluateBatch evaluates active assignment rules against many findings, listing
// the tenant's rule set ONCE (vs once per finding in EvaluateRules). Returns a
// map from finding ID to its matching results; findings with no match are
// omitted. Used by the ingest path to route a whole scan batch efficiently.
func (e *Engine) EvaluateBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (map[shared.ID][]Result, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	rules, err := e.acRepo.ListActiveRulesByPriority(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignment rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}

	needAsset := e.assetFor != nil && rulesNeedAsset(rules)
	out := make(map[shared.ID][]Result, len(findings))
	for _, f := range findings {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if f == nil {
			continue
		}
		if results := e.matchRules(ctx, tenantID, f, rules, needAsset); len(results) > 0 {
			out[f.ID()] = results
		}
	}

	e.logger.Info("assignment rules evaluated (batch)",
		"tenant_id", tenantID.String(),
		"total_rules", len(rules),
		"findings", len(findings),
		"matched_findings", len(out),
	)
	return out, nil
}

// matchRules evaluates a pre-listed rule set against one finding, resolving the
// finding's asset type only when needAssetType is set. Shared by EvaluateRules
// (single) and EvaluateBatch (bulk) so the matching logic stays in one place.
func (e *Engine) matchRules(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding, rules []*accesscontrol.AssignmentRule, needAsset bool) []Result {
	// Resolve the finding's asset ONCE, only when some rule filters by asset
	// type or asset tags: neither is carried on the finding.
	var facts AssetFacts
	if needAsset {
		facts = e.FactsFor(ctx, tenantID, finding)
	}

	seen := make(map[shared.ID]struct{})
	results := make([]Result, 0, len(rules))
	for _, rule := range rules {
		if e.MatchesConditions(rule.Conditions(), finding, facts) {
			gid := rule.TargetGroupID()
			if _, exists := seen[gid]; !exists {
				seen[gid] = struct{}{}
				results = append(results, Result{
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
	return results
}

// FactsFor resolves the facts of the finding's asset. A failed lookup returns
// empty facts (asset conditions then cannot match) and is logged.
func (e *Engine) FactsFor(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) AssetFacts {
	if e.assetFor == nil || finding == nil {
		return AssetFacts{}
	}
	aid := finding.AssetID()
	if aid.IsZero() {
		return AssetFacts{}
	}
	f, err := e.assetFor(ctx, tenantID, aid)
	if err != nil {
		e.logger.Warn("failed to resolve asset for assignment rules",
			"asset_id", aid.String(), "error", err)
		return AssetFacts{}
	}
	return f
}

// MatchesConditions checks if a finding matches the given conditions.
// All non-empty condition fields must match (AND logic).
// Empty conditions = catch-all (always matches).
// facts is optional: pass the finding's asset facts for the AssetTypes and
// AssetTags conditions (the asset's tags, not the finding's). A condition names types as a
// person wrote them (`host`, `website`); they are matched on the stored pair
// through the asset type registry (RFC-042 §6.3.8), so a rule on `website`
// matches a stored (application, website).
func (e *Engine) MatchesConditions(conds accesscontrol.AssignmentConditions, finding *vulnerability.Finding, facts ...AssetFacts) bool {
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
		var assetTags []string
		if len(facts) > 0 {
			assetTags = facts[0].Tags
		}
		if !hasAnyTag(assetTags, conds.AssetTags) {
			return false
		}
	}

	if conds.FilePathPattern != "" {
		if !matchesFilePathPattern(finding.FilePath(), conds.FilePathPattern) {
			return false
		}
	}

	if len(conds.AssetTypes) > 0 {
		var at asset.TypeRef
		if len(facts) > 0 {
			at = facts[0].Type
		}
		if at.Type == "" {
			// No asset type available — cannot match this condition
			return false
		}
		matched := false
		for _, name := range conds.AssetTypes {
			if asset.TypeNameMatches(name, at) {
				matched = true
				break
			}
		}
		if !matched {
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

// hasAnyTag checks if any of the asset's tags match any of the required tags.
func hasAnyTag(assetTags, requiredTags []string) bool {
	required := make(map[string]struct{}, len(requiredTags))
	for _, rt := range requiredTags {
		required[strings.ToLower(rt)] = struct{}{}
	}
	for _, ft := range assetTags {
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
