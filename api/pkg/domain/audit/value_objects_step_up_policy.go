package audit

// The organization's re-verification (step-up) policy
// (docs/architecture/step-up-reauth.md).

const (
	// ActionTenantStepUpPolicyChanged records a change of the policy, with
	// the rule of each tier before and after; asking less often is audited
	// high.
	ActionTenantStepUpPolicyChanged Action = "tenant.step_up_policy_changed"
)

var _ = registerActions("step_up_policy", map[Action]Severity{
	ActionTenantStepUpPolicyChanged: SeverityMedium,
})
