package audit

// CI runner identity and the CI gate (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).

const (
	ActionCITrustConfigCreated Action = "ci_trust_config.created"
	ActionCITrustConfigUpdated Action = "ci_trust_config.updated"
	ActionCITrustConfigDeleted Action = "ci_trust_config.deleted"

	// ActionCISettingsUpdated records a change of the tenant's CI settings
	// (OIDC required for CI results).
	ActionCISettingsUpdated Action = "ci_settings.updated"
	// ActionCIRunnerKeyRefused records a CI sensor's key refused because the
	// organization requires OIDC for CI (at most once per sensor every ten
	// minutes).
	ActionCIRunnerKeyRefused Action = "ci_run.runner_key_refused"

	// ActionCIRunTokenIssued records a CI job's OIDC token exchanged for a
	// run upload token (repository, actor, scan run id; never a token).
	ActionCIRunTokenIssued Action = "ci_run.token_issued"
	// ActionCIRunTokenRefused records a verified CI token that no trust
	// configuration admitted, or a replayed one.
	ActionCIRunTokenRefused Action = "ci_run.token_refused"
	// ActionCIRunResultsUploaded records a report a run uploaded (counts and
	// tool label; never finding content).
	ActionCIRunResultsUploaded Action = "ci_run.results_uploaded"
	// ActionCIRunEvaluated records a gate verdict.
	ActionCIRunEvaluated Action = "ci_run.evaluated"

	ActionCIGatePolicyCreated Action = "ci_gate_policy.created"
	ActionCIGatePolicyUpdated Action = "ci_gate_policy.updated"
	ActionCIGatePolicyDeleted Action = "ci_gate_policy.deleted"

	// Break-glass: created, revoked, and each time it lets a failing run pass.
	ActionCIGateOverrideCreated Action = "ci_gate_override.created"
	ActionCIGateOverrideRevoked Action = "ci_gate_override.revoked"
	ActionCIGateOverrideUsed    Action = "ci_gate_override.used"

	// ActionCIPipelineCreated records a new CI pipeline (the first verified
	// run of a workflow file of a repository).
	ActionCIPipelineCreated Action = "ci_pipeline.created"
	// ActionCIPipelinesRevoked records the scan workflows of a trust
	// configuration revoked because it was disabled, deleted or re-pointed.
	ActionCIPipelinesRevoked Action = "ci_pipeline.revoked"
	// ActionCIPipelineRetired records an administrator retiring a scan workflow
	// and the findings only it reported closing as source retired.
	ActionCIPipelineRetired Action = "ci_pipeline.retired"
	// ActionCIStaleSourceFindings records findings only a stale CI pipeline
	// reported moving to not observed (source stale).
	ActionCIStaleSourceFindings Action = "ci_pipeline.stale_source_findings"
	// A repository marked, or no longer marked, as expected to be covered.
	ActionCICoverageExpected   Action = "ci_coverage.expected"
	ActionCICoverageUnexpected Action = "ci_coverage.unexpected"
)

// Resource types of the CI actions.
const (
	ResourceTypeCITrustConfig  ResourceType = "ci_trust_config"
	ResourceTypeCIRun          ResourceType = "ci_run"
	ResourceTypeCIGatePolicy   ResourceType = "ci_gate_policy"
	ResourceTypeCIGateOverride ResourceType = "ci_gate_override"
	ResourceTypeCIPipeline     ResourceType = "ci_pipeline"
	ResourceTypeCISettings     ResourceType = "ci_settings"
)

var _ = registerActions("ci", map[Action]Severity{
	ActionCITrustConfigCreated:  SeverityHigh,
	ActionCITrustConfigUpdated:  SeverityHigh,
	ActionCITrustConfigDeleted:  SeverityMedium,
	ActionCISettingsUpdated:     SeverityMedium,
	ActionCIRunnerKeyRefused:    SeverityMedium,
	ActionCIRunTokenIssued:      SeverityLow,
	ActionCIRunTokenRefused:     SeverityMedium,
	ActionCIRunResultsUploaded:  SeverityLow,
	ActionCIRunEvaluated:        SeverityLow,
	ActionCIGatePolicyCreated:   SeverityMedium,
	ActionCIGatePolicyUpdated:   SeverityMedium,
	ActionCIGatePolicyDeleted:   SeverityMedium,
	ActionCIGateOverrideCreated: SeverityHigh,
	ActionCIGateOverrideRevoked: SeverityMedium,
	ActionCIGateOverrideUsed:    SeverityHigh,
	ActionCIPipelineCreated:     SeverityLow,
	ActionCIPipelinesRevoked:    SeverityMedium,
	ActionCIPipelineRetired:     SeverityHigh,
	ActionCIStaleSourceFindings: SeverityLow,
	ActionCICoverageExpected:    SeverityLow,
	ActionCICoverageUnexpected:  SeverityLow,
})

func init() {
	for _, r := range []ResourceType{ResourceTypeCITrustConfig, ResourceTypeCIRun, ResourceTypeCIGatePolicy, ResourceTypeCIGateOverride, ResourceTypeCIPipeline, ResourceTypeCISettings} {
		configResourceTypes[r] = struct{}{}
	}
}
