package coverage

// The info pass of vuln.templates (docs/architecture/asset-coverage.md,
// "Info pass"; docs/architecture/scan-stages.md §1.5): the regular
// vuln.templates pass runs severity low to critical on its cadence; the info
// pass is the same stage at severity info only, on its own slower cadence,
// so no template runs twice. It has its own ledger key, the capability
// "vuln.templates_info", so its state, gaps and cadence never mix with the
// regular pass. Info matches are filed as info exposures, not findings
// (docs/architecture/exposure-taxonomy.md).

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CapabilityVulnTemplatesInfo is the ledger key of the info pass.
const CapabilityVulnTemplatesInfo = "vuln.templates_info"

// stageVulnTemplates is the stage both passes run.
const stageVulnTemplates = "vuln.templates"

// ReasonInfoPassOff marks an info pair parked because the organization turned
// the info pass off. Not a gap; it comes back when the pass is turned on.
const ReasonInfoPassOff = "info_pass_off"

// Bounds of the organization's info interval, in days.
const (
	DefaultInfoDays = 30
	MinInfoDays     = 7
	MaxInfoDays     = 90
)

// InfoChangeMinSpacing is the least time between two info passes of one
// asset that a change signal (technologies or web surface) may cause: the
// shortest interval, so a busy site never runs the info templates more often
// than the fastest cadence allows.
const InfoChangeMinSpacing = MinInfoDays * 24 * time.Hour

// InfoSeverity is the one severity of the info pass.
const InfoSeverity = "info"

// IsInfoCapability reports whether c is the info pass.
func IsInfoCapability(c string) bool { return c == CapabilityVulnTemplatesInfo }

// StageKeyOf is the stage catalog key a ledger capability runs: the info
// pass runs the vuln.templates stage; any other capability is its own stage.
func StageKeyOf(capability string) string {
	if IsInfoCapability(capability) {
		return stageVulnTemplates
	}
	return capability
}

// InfoPolicy is one organization's info pass setting.
type InfoPolicy struct {
	// On: the info pass runs. Default on.
	On bool
	// Every is the interval between two info passes of an asset.
	Every time.Duration
}

// DefaultInfoPolicy is the default: on, every 30 days.
func DefaultInfoPolicy() InfoPolicy {
	return InfoPolicy{On: true, Every: DefaultInfoDays * 24 * time.Hour}
}

// InfoPolicyReader reads an organization's info pass setting.
type InfoPolicyReader interface {
	InfoPolicy(ctx context.Context, tenantID shared.ID) (InfoPolicy, error)
}

// ApplyInfoPolicy returns rules as they hold for the organization: the info
// rule is dropped when the pass is off, else it carries the organization's
// interval. rules is not changed.
func ApplyInfoPolicy(rules []Rule, p InfoPolicy) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if IsInfoCapability(r.Capability) {
			if !p.On {
				continue
			}
			if p.Every > 0 {
				r.Every = p.Every
			}
		}
		out = append(out, r)
	}
	return out
}
