package audit

// The organization's API key policy (docs/architecture/api-keys.md).

const (
	// ActionTenantAPIKeyPolicyUpdated records a change of the maximum
	// lifetime of new API keys; a longer maximum is audited high.
	ActionTenantAPIKeyPolicyUpdated Action = "tenant.api_key_policy_updated"
)

var _ = registerActions("api_key_policy", map[Action]Severity{
	ActionTenantAPIKeyPolicyUpdated: SeverityMedium,
})
