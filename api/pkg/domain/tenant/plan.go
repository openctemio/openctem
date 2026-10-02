package tenant

// Plan represents a tenant's module configuration.
// In OSS edition, all tenants have unlimited access.
type Plan string

const (
	// PlanFree is the only plan in OSS edition - provides full access
	PlanFree Plan = "free"
)

// IsValid checks if the plan is valid.
func (p Plan) IsValid() bool {
	return p == PlanFree
}

// String returns the string representation of the plan.
func (p Plan) String() string {
	return string(p)
}

// PlanLimits defines the limits for each plan.
// In OSS edition, all limits are unlimited (-1).
type PlanLimits struct {
	MaxMembers    int
	MaxAssets     int
	MaxScansMonth int
	SSO           bool
	AuditLog      bool
	APIAccess     bool
}

// GetLimits returns the limits for this plan.
// In OSS edition, all features are unlimited.
func (p Plan) GetLimits() PlanLimits {
	return PlanLimits{
		MaxMembers:    -1, // unlimited
		MaxAssets:     -1,
		MaxScansMonth: -1,
		SSO:           true,
		AuditLog:      true,
		APIAccess:     true,
	}
}

// ParsePlan parses a string to a Plan.
func ParsePlan(s string) (Plan, bool) {
	// In OSS edition, always return free plan
	return PlanFree, true
}
