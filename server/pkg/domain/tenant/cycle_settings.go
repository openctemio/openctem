package tenant

// SectionCycles is the settings section key of the CTEM cycle policy.
const SectionCycles = "cycles"

// CycleSettings is the organization's CTEM cycle policy.
type CycleSettings struct {
	// EnforceCoverageSLO refuses to close a cycle whose validation coverage is
	// below the coverage thresholds (validation.DefaultThresholds). Off (the
	// default): the cycle closes and the shortfall is logged and shown in the
	// cycle's evaluation.
	EnforceCoverageSLO bool `json:"enforce_coverage_slo"`
}

// UpdateCycleSettings updates only the CTEM cycle policy.
func (t *Tenant) UpdateCycleSettings(cs CycleSettings) error {
	settings := t.TypedSettings()
	settings.Cycles = cs
	return t.UpdateSettings(settings)
}
