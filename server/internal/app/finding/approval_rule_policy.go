package finding

// Suppression rules under the approval policy
// (api/docs/rfcs/RFC-111-approval-policy.md): a rule is evaluated over the
// worst open finding it matches, with the organization's policy and security
// pool; the approver pool is the members who may approve rules, minus the
// requester and the owners of the matched findings' assets.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

// rulePolicyInputs reads the facts, owners and approvers of a rule
// (*postgres.SuppressionRepository).
type rulePolicyInputs interface {
	RulePolicyInputs(ctx context.Context, rule *suppression.Rule, limit int) ([]approvalpolicy.Facts, []shared.ID, []shared.ID, error)
}

// RulePolicyEvaluator evaluates suppression rules (suppression.PolicySource).
type RulePolicyEvaluator struct {
	svc   *VulnerabilityService
	rules rulePolicyInputs
}

var _ suppression.PolicySource = (*RulePolicyEvaluator)(nil)

// NewRulePolicyEvaluator returns the evaluator of suppression rules.
func NewRulePolicyEvaluator(svc *VulnerabilityService, rules rulePolicyInputs) *RulePolicyEvaluator {
	return &RulePolicyEvaluator{svc: svc, rules: rules}
}

// EvaluateRule evaluates rule under its organization's policy now.
func (e *RulePolicyEvaluator) EvaluateRule(ctx context.Context, rule *suppression.Rule) (approvalpolicy.Result, error) {
	op, err := e.svc.orgApprovalPolicy(ctx, rule.TenantID())
	if err != nil {
		return approvalpolicy.Result{}, err
	}
	facts, owners, approvers, err := e.rules.RulePolicyInputs(ctx, rule, suppression.MaxFindingsAppliedOnApprove)
	if err != nil {
		return approvalpolicy.Result{}, err
	}
	inPool, err := e.svc.securityPoolMembers(ctx, rule.TenantID(), op)
	if err != nil {
		return approvalpolicy.Result{}, err
	}
	cands := make([]approvalpolicy.Candidate, 0, len(approvers))
	for _, id := range approvers {
		cands = append(cands, approvalpolicy.Candidate{UserID: id, InSecurityPool: inPool[id]})
	}
	return approvalpolicy.Evaluate(op.policy, approvalpolicy.Request{
		Kind: suppression.KindOf(rule.SuppressionType()), Facts: approvalpolicy.WorstFacts(facts),
		RequesterID: rule.RequestedBy(), AssetOwners: owners, Approvers: cands,
		SecurityPoolConfigured: op.poolConfigured,
	}), nil
}
