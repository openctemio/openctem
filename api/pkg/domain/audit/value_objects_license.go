package audit

// License policy of the organization (api/docs/architecture/software-components.md).

// ActionTenantLicensePolicyUpdated records a change to the organization's
// license policy (before/after in the changes).
const ActionTenantLicensePolicyUpdated Action = "tenant.license_policy_updated"

var _ = registerActions("tenant", map[Action]Severity{
	ActionTenantLicensePolicyUpdated: SeverityMedium,
})
