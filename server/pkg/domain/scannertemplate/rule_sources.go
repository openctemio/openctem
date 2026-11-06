package scannertemplate

// Rule sources (docs/architecture/rule-sources.md): which detection rules a
// scan runs — the platform's rules (the sensor's managed template or rule
// pack), the organization's own scanner templates, or both together in one
// tool run.

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RuleSources is which detection rules a scan runs.
type RuleSources string

const (
	// RuleSourcesBoth runs the platform's rules and the organization's
	// templates together (the default).
	RuleSourcesBoth RuleSources = "both"
	// RuleSourcesPlatform runs only the platform's rules; the scan's custom
	// templates are not sent.
	RuleSourcesPlatform RuleSources = "platform"
	// RuleSourcesTenant runs only the organization's own templates.
	RuleSourcesTenant RuleSources = "tenant"
)

// SensorCapabilityRuleSources is what a sensor reports when its scanners
// honor a job's rule sources (sdk-go core.CapabilityRuleSources). A
// tenant-only job is claimable only by such a sensor: an older sensor would
// also run the platform's rules.
const SensorCapabilityRuleSources = "rule.sources@1"

// PayloadKeyRuleSources is the scan command payload key the sensor reads
// (sdk-go ScanCommandPayload.RuleSources).
const PayloadKeyRuleSources = "rule_sources"

// IsValid reports whether r is one of the three rule sources.
func (r RuleSources) IsValid() bool {
	switch r {
	case RuleSourcesBoth, RuleSourcesPlatform, RuleSourcesTenant:
		return true
	}
	return false
}

// RunsTenant reports whether the organization's templates run.
func (r RuleSources) RunsTenant() bool { return r == RuleSourcesBoth || r == RuleSourcesTenant }

// ParseRuleSources reads a rule sources value: "" stays "" (not set: the
// scan inherits its profile's, and a profile defaults to both); anything
// else must be one of the three.
func ParseRuleSources(s string) (RuleSources, error) {
	v := RuleSources(strings.ToLower(strings.TrimSpace(s)))
	if v == "" || v.IsValid() {
		return v, nil
	}
	return "", shared.NewDomainError("VALIDATION",
		"rule_sources must be both, platform or tenant", shared.ErrValidation)
}

// EffectiveRuleSources is what a run uses: the scan's own setting, else its
// profile's, else both.
func EffectiveRuleSources(scanValue, profileValue RuleSources) RuleSources {
	switch {
	case scanValue.IsValid():
		return scanValue
	case profileValue.IsValid():
		return profileValue
	default:
		return RuleSourcesBoth
	}
}
