package ingest

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// resolutionSuppressed is the resolution note stamped on a finding that an
// approved suppression rule matched at ingest time; finding_suppressions names
// the rule. It is also a sentinel the auto-reopen query excludes (see
// FindingRepository.AutoReopenByFingerprintsBatch).
const resolutionSuppressed = "suppressed"

// suppressionDisposition is the status a rule of type t gives a finding it
// matches (research 18 F7, owner decision O9): a disposition, never resolved,
// so fix rate and MTTR count real fixes only. A false-positive rule marks the
// finding false_positive; accepted-risk and won't-fix rules mark it accepted.
func suppressionDisposition(t suppression.SuppressionType) vulnerability.FindingStatus {
	if t == suppression.SuppressionTypeFalsePositive {
		return vulnerability.FindingStatusFalsePositive
	}
	return vulnerability.FindingStatusAccepted
}

// SuppressionChecker loads a tenant's active (approved, non-expired) suppression
// rules and records which rule suppressed a finding. Implemented by
// *suppression.Service. Nil-safe at the call sites: when unwired, ingest behaves
// exactly as before.
type SuppressionChecker interface {
	// ListActiveRules returns the tenant's approved, non-expired rules.
	ListActiveRules(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error)
	// ApplySuppression records that a finding was suppressed by a rule
	// (finding_suppressions), for audit and later un-suppression.
	ApplySuppression(ctx context.Context, findingID, ruleID shared.ID) error
}

// SetSuppressionChecker wires approved suppression-rule enforcement into the
// ingest finding path. Nil-safe: when unwired, findings are never suppressed at
// ingest (prior behavior).
func (p *FindingProcessor) SetSuppressionChecker(checker SuppressionChecker) {
	p.suppressionChecker = checker
}

// ModuleGuard reports the modules a tenant has disabled (explicitly, or by
// leaving them out of its bundles). Satisfied by *module.ModuleService.
type ModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// suppressionsModule is the module id of the suppressions feature.
const suppressionsModule = "suppressions"

// SetSuppressionModuleGuard makes ingest honour the suppressions module
// toggle: a tenant with the module off gets its findings as reported. Nil
// (unwired) keeps suppression on, as before.
func (p *FindingProcessor) SetSuppressionModuleGuard(guard ModuleGuard) {
	p.suppressionModules = guard
}

// applySuppressions gives each NEW finding that an active suppression rule
// matches the rule's disposition (false_positive or accepted, resolution
// "suppressed") BEFORE it is persisted, so it lands out of the open backlog
// instead of appearing and then being closed on a later pass. It is never
// marked resolved: a suppression is not a fix.
//
// Active rules are loaded ONCE per batch (tenant-scoped), never per finding.
// Returns a map of newFindings index -> matching rule id so the finding→rule
// link can be recorded for audit AFTER the rows are persisted
// (finding_suppressions.finding_id is an FK to a persisted finding). A nil
// checker, a lookup error, or no active rules is a no-op — ingest never fails on
// suppression.
func (p *FindingProcessor) applySuppressions(
	ctx context.Context,
	tenantID shared.ID,
	newFindings []*vulnerability.Finding,
) map[int]shared.ID {
	if p.suppressionChecker == nil || len(newFindings) == 0 {
		return nil
	}
	if p.suppressionModules != nil && p.suppressionModules.TenantDisabledModules(ctx, tenantID.String())[suppressionsModule] {
		return nil
	}

	rules, err := p.suppressionChecker.ListActiveRules(ctx, tenantID)
	if err != nil {
		p.logger.Warn("failed to load active suppression rules; skipping suppression", "error", err)
		return nil
	}
	if len(rules) == 0 {
		return nil
	}

	decisions := make(map[int]shared.ID)
	for i, f := range newFindings {
		match := suppression.FindingMatch{
			ToolName: f.ToolName(),
			RuleID:   f.RuleID(),
			FilePath: f.FilePath(),
			AssetID:  f.AssetID(),
		}
		for _, rule := range rules {
			// Rule.Matches re-checks IsActive(), so a pending/rejected/expired
			// rule can never suppress even if one slipped into the list.
			if !rule.Matches(match) {
				continue
			}
			// resolvedBy nil = system disposition (no human actor); the rule
			// was approved by a person (separation of duties).
			if err := f.UpdateStatus(suppressionDisposition(rule.SuppressionType()), resolutionSuppressed, nil); err != nil {
				p.logger.Warn("failed to apply suppression disposition",
					"error", err, "fingerprint", f.Fingerprint())
				break
			}
			decisions[i] = rule.ID()
			break
		}
	}
	return decisions
}

// recordSuppressions records, for each successfully-persisted suppressed finding,
// the finding→rule link (finding_suppressions) so an ingest suppression is
// traceable and can be un-suppressed if the rule is later deleted/rejected.
// Best-effort: a recording error is logged, never fatal. Returns the number of
// links recorded. errorsByIndex is the batch-create error map — an entry (a
// non-empty string) means the finding at that index failed to persist and must
// not be linked.
func (p *FindingProcessor) recordSuppressions(
	ctx context.Context,
	newFindings []*vulnerability.Finding,
	decisions map[int]shared.ID,
	errorsByIndex map[int]string,
) int {
	if p.suppressionChecker == nil || len(decisions) == 0 {
		return 0
	}
	recorded := 0
	for idx, ruleID := range decisions {
		if errorsByIndex != nil && errorsByIndex[idx] != "" {
			continue // finding failed to persist — nothing to link
		}
		f := newFindings[idx]
		if err := p.suppressionChecker.ApplySuppression(ctx, f.ID(), ruleID); err != nil {
			p.logger.Warn("failed to record finding suppression",
				"error", err, "finding_id", f.ID().String(), "rule_id", ruleID.String())
			continue
		}
		recorded++
	}
	return recorded
}
