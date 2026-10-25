package sla

import (
	"context"
	"time"

	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Explanation says why a finding's SLA deadline is the date it is: which
// policy governs it, whether the priority class or the severity set the
// window, the window in days, the known exploited cap, and when the clock
// started. It is computed with the same choice the deadline writers make
// (CalculateSLADeadlineForPriority and the KEV cap), so the detail page and
// the stored deadline cannot tell different stories.
type Explanation struct {
	PolicyID   string
	PolicyName string
	// PolicyScope: "asset" (an asset's own policy), "organization" (the
	// organization's default) or "platform" (no policy configured).
	PolicyScope string
	// Basis: "priority" (the class window), "severity" (no class window
	// applies) or "none" (no SLA: informational under a policy without one).
	Basis      string
	Days       int
	KEVCapDays int
}

// ExplainDeadline explains the deadline of a finding with this asset (""
// for none), priority class and severity.
func (s *Service) ExplainDeadline(ctx context.Context, tenantID, assetID, priorityClass string, severity vulnerability.Severity) (*Explanation, error) {
	var eff *EffectivePolicy
	var err error
	if assetID != "" {
		eff, err = s.GetEffectiveAssetPolicy(ctx, tenantID, assetID)
	} else {
		eff, err = s.GetEffectiveTenantPolicy(ctx, tenantID)
	}
	if err != nil {
		return nil, err
	}
	return explain(eff, priorityClass, severity), nil
}

func explain(eff *EffectivePolicy, priorityClass string, severity vulnerability.Severity) *Explanation {
	p := eff.Policy
	out := &Explanation{PolicyID: p.ID().String(), PolicyName: p.Name(), KEVCapDays: p.KEVCapDays()}
	switch {
	case eff.PlatformDefault:
		out.PolicyID, out.PolicyScope, out.KEVCapDays = "", "platform", sladom.DefaultKEVCapDays
	case p.AssetID() != nil:
		out.PolicyScope = "asset"
	default:
		out.PolicyScope = "organization"
	}
	if eff.PlatformDefault {
		// Same windows as deadlineForPriority with no policy.
		if severity.IsInformational() {
			out.Basis = "none"
			return out
		}
		if days := sladom.DefaultPriorityDays[priorityClass]; days > 0 {
			out.Basis, out.Days = "priority", days
			return out
		}
		out.Basis, out.Days = "severity", sladom.DefaultSLADays[severity.String()]
		return out
	}
	if severity.IsInformational() && !p.InformationalHasSLA() {
		out.Basis = "none"
		return out
	}
	if days := p.GetDaysForPriorityClass(priorityClass); days > 0 {
		out.Basis, out.Days = "priority", days
		return out
	}
	out.Basis, out.Days = "severity", p.GetDaysForSeverity(severity.String())
	if out.Days <= 0 {
		out.Basis, out.Days = "none", 0
	}
	return out
}

// ExpectedDeadline is the deadline the explanation gives for a clock that
// started at start, with the KEV cap when the finding is in KEV; zero when
// there is no SLA.
func (e *Explanation) ExpectedDeadline(start time.Time, inKEV bool) (time.Time, bool) {
	if e == nil || e.Days <= 0 {
		return time.Time{}, false
	}
	d := start.Add(time.Duration(e.Days) * 24 * time.Hour)
	if inKEV && e.KEVCapDays > 0 {
		if c := start.Add(time.Duration(e.KEVCapDays) * 24 * time.Hour); c.Before(d) {
			return c, true
		}
	}
	return d, false
}
