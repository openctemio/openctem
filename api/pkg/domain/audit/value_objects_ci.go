package audit

// CI runner identity and the CI gate (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).

const (
	ActionCITrustConfigCreated Action = "ci_trust_config.created"
	ActionCITrustConfigUpdated Action = "ci_trust_config.updated"
	ActionCITrustConfigDeleted Action = "ci_trust_config.deleted"

	// ActionCIRunTokenIssued records a CI job's OIDC token exchanged for a
	// run upload token (repository, actor, pipeline run id; never a token).
	ActionCIRunTokenIssued Action = "ci_run.token_issued"
	// ActionCIRunTokenRefused records a verified CI token that no trust
	// configuration admitted, or a replayed one.
	ActionCIRunTokenRefused Action = "ci_run.token_refused"
	// ActionCIRunEvaluated records a gate verdict.
	ActionCIRunEvaluated Action = "ci_run.evaluated"

	ActionCIGatePolicyCreated Action = "ci_gate_policy.created"
	ActionCIGatePolicyUpdated Action = "ci_gate_policy.updated"
	ActionCIGatePolicyDeleted Action = "ci_gate_policy.deleted"

	// Break-glass: created, revoked, and each time it lets a failing run pass.
	ActionCIGateOverrideCreated Action = "ci_gate_override.created"
	ActionCIGateOverrideRevoked Action = "ci_gate_override.revoked"
	ActionCIGateOverrideUsed    Action = "ci_gate_override.used"
)

// Resource types of the CI actions.
const (
	ResourceTypeCITrustConfig  ResourceType = "ci_trust_config"
	ResourceTypeCIRun          ResourceType = "ci_run"
	ResourceTypeCIGatePolicy   ResourceType = "ci_gate_policy"
	ResourceTypeCIGateOverride ResourceType = "ci_gate_override"
)

var _ = registerActions("ci", map[Action]Severity{
	ActionCITrustConfigCreated:  SeverityHigh,
	ActionCITrustConfigUpdated:  SeverityHigh,
	ActionCITrustConfigDeleted:  SeverityMedium,
	ActionCIRunTokenIssued:      SeverityLow,
	ActionCIRunTokenRefused:     SeverityMedium,
	ActionCIRunEvaluated:        SeverityLow,
	ActionCIGatePolicyCreated:   SeverityMedium,
	ActionCIGatePolicyUpdated:   SeverityMedium,
	ActionCIGatePolicyDeleted:   SeverityMedium,
	ActionCIGateOverrideCreated: SeverityHigh,
	ActionCIGateOverrideRevoked: SeverityMedium,
	ActionCIGateOverrideUsed:    SeverityHigh,
})

func init() {
	for _, r := range []ResourceType{ResourceTypeCITrustConfig, ResourceTypeCIRun, ResourceTypeCIGatePolicy, ResourceTypeCIGateOverride} {
		configResourceTypes[r] = struct{}{}
	}
}
