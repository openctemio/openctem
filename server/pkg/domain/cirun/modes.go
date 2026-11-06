package cirun

// Per-capability and per-rule modes of a gate policy
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, G-7).

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Finding modes, strongest first.
const (
	// FindingModeBlock: a finding over the policy's thresholds fails the gate.
	FindingModeBlock = "block"
	// FindingModeComment: listed on the verdict and the pull request, never
	// fails the gate.
	FindingModeComment = "comment"
	// FindingModeMonitor: recorded on the run only.
	FindingModeMonitor = "monitor"
)

// Capabilities a mode can name.
var modeCapabilities = map[string]bool{string(CapabilitySAST): true, string(CapabilitySCA): true,
	string(CapabilitySecrets): true, string(CapabilityIaC): true, "container": true}

const (
	maxModeRules  = 200
	maxModeRuleID = 500
)

// PolicyModes sets a mode per capability and per rule id; a rule's mode wins
// over its capability's, and everything else blocks.
type PolicyModes struct {
	Capabilities map[string]string `json:"capabilities,omitempty"`
	Rules        map[string]string `json:"rules,omitempty"`
}

func modeRank(m string) int {
	switch m {
	case FindingModeBlock:
		return 3
	case FindingModeComment:
		return 2
	case FindingModeMonitor:
		return 1
	}
	return 0
}

// Validate checks names and values.
func (m PolicyModes) Validate() error {
	for c, v := range m.Capabilities {
		if !modeCapabilities[c] {
			return fmt.Errorf("%w: modes: unknown capability %q (sast, sca, secrets, iac, container)", shared.ErrValidation, c)
		}
		if modeRank(v) == 0 {
			return fmt.Errorf("%w: modes: %q must be block, comment or monitor", shared.ErrValidation, v)
		}
	}
	if len(m.Rules) > maxModeRules {
		return fmt.Errorf("%w: modes: at most %d rules", shared.ErrValidation, maxModeRules)
	}
	for r, v := range m.Rules {
		if strings.TrimSpace(r) == "" || len(r) > maxModeRuleID || strings.ContainsAny(r, "\n\r") {
			return fmt.Errorf("%w: modes: invalid rule id", shared.ErrValidation)
		}
		if modeRank(v) == 0 {
			return fmt.Errorf("%w: modes: %q must be block, comment or monitor", shared.ErrValidation, v)
		}
	}
	return nil
}

// For returns the mode of a finding.
func (m PolicyModes) For(f RunFinding) string {
	if v, ok := m.Rules[f.RuleID]; ok && f.RuleID != "" {
		return v
	}
	if v, ok := m.Capabilities[FindingCapability(f)]; ok {
		return v
	}
	return FindingModeBlock
}

// strictestModes merges two policies' modes keeping, for each key, the
// stronger value. A key one policy does not set means block there, so it is
// dropped (block is the default).
func strictestModes(a, b PolicyModes) PolicyModes {
	merge := func(x, y map[string]string) map[string]string {
		var out map[string]string
		for k, xv := range x {
			yv, ok := y[k]
			if !ok {
				continue
			}
			v := xv
			if modeRank(yv) > modeRank(xv) {
				v = yv
			}
			if v == FindingModeBlock {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
		return out
	}
	return PolicyModes{Capabilities: merge(a.Capabilities, b.Capabilities), Rules: merge(a.Rules, b.Rules)}
}

// FindingCapability names the scan capability that reports a finding.
func FindingCapability(f RunFinding) string {
	switch f.Source {
	case string(CapabilitySAST), string(CapabilitySCA), string(CapabilityIaC), "container":
		return f.Source
	case "secret":
		return string(CapabilitySecrets)
	}
	switch f.FindingType {
	case "secret":
		return string(CapabilitySecrets)
	case "misconfiguration":
		return string(CapabilityIaC)
	}
	return ""
}
