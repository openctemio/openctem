package scope

// Remedies are the ranked choices a scan form offers for one refused target:
// what the person editing the scan can change in the scan itself (run it on
// the organization's own sensor, lower its intensity, drop the target) or
// the one scope action that unblocks it most often (verify the domain). The
// first is the one to show as the primary action. They are computed from
// the caller's own, permission-filtered fixes and from facts about the
// caller's organization; nothing here grants anything, and the scan is
// checked again when it is saved and when it runs.

// Remedy actions.
const (
	RemedyRunOnTenantSensor = "run_on_tenant_sensor"
	RemedyVerifyDomain      = "verify_domain"
	RemedyLowerIntensity    = "lower_intensity"
	RemedyRemove            = "remove"
)

// Remedy is one ranked choice for a refused target.
type Remedy struct {
	// Action: run_on_tenant_sensor, verify_domain, lower_intensity or remove.
	Action string `json:"action" enums:"run_on_tenant_sensor,verify_domain,lower_intensity,remove"`
	// Domain to verify (verify_domain).
	Domain string `json:"domain,omitempty"`
	// Tier is the highest probe tier (0 passive, 1 safe active) at which
	// the target is allowed (lower_intensity).
	Tier *int `json:"tier,omitempty"`
}

// RemedyInput is what ranking the remedies of one refusal needs.
type RemedyInput struct {
	// Code is the refusal code.
	Code string
	// Fixes are the refusal's fixes, already filtered for the caller.
	Fixes []Fix
	// Preference is the scan's sensor preference (auto, tenant, platform).
	Preference string
	// TenantSensor: one of the organization's own sensors could take the job
	// now (online, or online and busy).
	TenantSensor bool
	// LowerTier, when set, is the highest lower tier at which the gate lets
	// the target through (found by checking it again at that tier).
	LowerTier *int
}

// RankRemedies lists the remedies for one refusal, best first: running on
// the organization's own sensor when one is online and only platform sensors
// refuse the target, then verifying the domain, then a lower intensity, and
// removing the target last (always offered).
func RankRemedies(in RemedyInput) []Remedy {
	out := make([]Remedy, 0, 4)
	sensorHelps := in.Code == RefusalProofRequired || in.Code == RefusalProgramPlatform
	if sensorHelps && in.TenantSensor && in.Preference != "tenant" {
		out = append(out, Remedy{Action: RemedyRunOnTenantSensor})
	}
	for _, f := range in.Fixes {
		if f.Action == FixVerifyDomain && f.Domain != "" {
			out = append(out, Remedy{Action: RemedyVerifyDomain, Domain: f.Domain})
			break
		}
	}
	if in.LowerTier != nil && *in.LowerTier >= int(TierPassive) {
		tier := *in.LowerTier
		out = append(out, Remedy{Action: RemedyLowerIntensity, Tier: &tier})
	}
	return append(out, Remedy{Action: RemedyRemove})
}

// TierSensitive reports whether a refusal with this code may pass at a lower
// probe tier (the covering entry's ceiling, or the low-impact profile).
func TierSensitive(code string) bool {
	return code == RefusalTierExceeds || code == RefusalLowImpact
}
