package assetgroup

// Environment represents the deployment environment of an asset group.
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentTesting     Environment = "testing"
)

func (e Environment) String() string {
	return string(e)
}

func (e Environment) IsValid() bool {
	switch e {
	case EnvironmentProduction, EnvironmentStaging, EnvironmentDevelopment, EnvironmentTesting:
		return true
	}
	return false
}

func ParseEnvironment(s string) (Environment, bool) {
	e := Environment(s)
	return e, e.IsValid()
}

func AllEnvironments() []Environment {
	return []Environment{
		EnvironmentProduction,
		EnvironmentStaging,
		EnvironmentDevelopment,
		EnvironmentTesting,
	}
}

// Criticality represents the business criticality of an asset group.
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
)

func (c Criticality) String() string {
	return string(c)
}

func (c Criticality) IsValid() bool {
	switch c {
	case CriticalityCritical, CriticalityHigh, CriticalityMedium, CriticalityLow:
		return true
	}
	return false
}

func ParseCriticality(s string) (Criticality, bool) {
	c := Criticality(s)
	return c, c.IsValid()
}

func AllCriticalities() []Criticality {
	return []Criticality{
		CriticalityCritical,
		CriticalityHigh,
		CriticalityMedium,
		CriticalityLow,
	}
}

// Score returns a numeric score for the criticality (for risk calculations).
func (c Criticality) Score() int {
	switch c {
	case CriticalityCritical:
		return 100
	case CriticalityHigh:
		return 75
	case CriticalityMedium:
		return 50
	case CriticalityLow:
		return 25
	default:
		return 0
	}
}
