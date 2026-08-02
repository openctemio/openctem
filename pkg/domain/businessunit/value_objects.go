package businessunit

// Criticality represents the business criticality of a business unit.
// Values mirror the platform-wide criticality scale used by asset groups
// and business services (critical|high|medium|low).
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
)

func (c Criticality) String() string { return string(c) }

func (c Criticality) IsValid() bool {
	switch c {
	case CriticalityCritical, CriticalityHigh, CriticalityMedium, CriticalityLow:
		return true
	}
	return false
}

// ParseCriticality parses a string into a Criticality, reporting validity.
func ParseCriticality(s string) (Criticality, bool) {
	c := Criticality(s)
	return c, c.IsValid()
}

// RiskTolerance represents how much residual risk a business unit accepts.
type RiskTolerance string

const (
	RiskToleranceLow    RiskTolerance = "low"
	RiskToleranceMedium RiskTolerance = "medium"
	RiskToleranceHigh   RiskTolerance = "high"
)

func (t RiskTolerance) String() string { return string(t) }

func (t RiskTolerance) IsValid() bool {
	switch t {
	case RiskToleranceLow, RiskToleranceMedium, RiskToleranceHigh:
		return true
	}
	return false
}

// ParseRiskTolerance parses a string into a RiskTolerance, reporting validity.
func ParseRiskTolerance(s string) (RiskTolerance, bool) {
	t := RiskTolerance(s)
	return t, t.IsValid()
}
