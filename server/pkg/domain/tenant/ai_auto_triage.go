package tenant

// The organization's automatic AI triage policy (docs/architecture/ai-triage.md,
// "Automatic triage"): whether new findings are sent to the AI provider
// without a person asking, for which severities, and after what delay.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxAutoTriageDelaySeconds bounds the wait before a new finding is
// triaged automatically (one hour).
const MaxAutoTriageDelaySeconds = 3600

// autoTriageSeverityOrder is the order severities are stored and shown in.
var autoTriageSeverityOrder = []string{"critical", "high", "medium", "low", "info"}

// AutoTriagePolicy is the automatic triage part of AISettings.
type AutoTriagePolicy struct {
	Enabled      bool
	Severities   []string
	DelaySeconds int
}

// AutoTriagePolicy returns the policy part of the settings.
func (s AISettings) AutoTriagePolicy() AutoTriagePolicy {
	return AutoTriagePolicy{
		Enabled:      s.AutoTriageEnabled,
		Severities:   slices.Clone(s.AutoTriageSeverities),
		DelaySeconds: s.AutoTriageDelaySeconds,
	}
}

// Normalized validates the policy and returns it with the severities lower
// case, deduplicated and in severity order.
func (p AutoTriagePolicy) Normalized() (AutoTriagePolicy, error) {
	seen := make(map[string]bool, len(p.Severities))
	for _, sev := range p.Severities {
		sev = strings.ToLower(strings.TrimSpace(sev))
		if !slices.Contains(autoTriageSeverityOrder, sev) {
			return AutoTriagePolicy{}, fmt.Errorf("%w: invalid severity %q", shared.ErrValidation, sev)
		}
		seen[sev] = true
	}
	out := AutoTriagePolicy{Enabled: p.Enabled, Severities: []string{}, DelaySeconds: p.DelaySeconds}
	for _, sev := range autoTriageSeverityOrder {
		if seen[sev] {
			out.Severities = append(out.Severities, sev)
		}
	}
	if p.DelaySeconds < 0 || p.DelaySeconds > MaxAutoTriageDelaySeconds {
		return AutoTriagePolicy{}, fmt.Errorf("%w: delay_seconds must be 0 to %d", shared.ErrValidation, MaxAutoTriageDelaySeconds)
	}
	if p.Enabled && len(out.Severities) == 0 {
		return AutoTriagePolicy{}, fmt.Errorf("%w: choose at least one severity to triage automatically", shared.ErrValidation)
	}
	return out, nil
}

// AutoTriageLoosened reports a change that sends more finding content to the
// AI provider without a person asking: turning automatic triage on, or
// adding a severity while it is on. Turning it off, removing severities and
// any change of the delay are not loosening.
func AutoTriageLoosened(before, after AutoTriagePolicy) bool {
	if !after.Enabled {
		return false
	}
	if !before.Enabled {
		return true
	}
	for _, sev := range after.Severities {
		if !slices.ContainsFunc(before.Severities, func(b string) bool { return strings.EqualFold(b, sev) }) {
			return true
		}
	}
	return false
}

// AutoTriagePolicyRepository writes the organization's automatic triage
// policy (the policy column of tenant_ai_settings); every key is written, so
// the platform defaults no longer apply once an administrator saved it.
type AutoTriagePolicyRepository interface {
	SaveAutoTriagePolicy(ctx context.Context, tenantID shared.ID, p AutoTriagePolicy) error
}
