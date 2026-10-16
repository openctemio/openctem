package approvalpolicy

import (
	"strings"
	"time"
)

// Facts are the facts of a finding that decide its risk class. The caller
// reads them on the server (never from the client).
type Facts struct {
	// Severity is critical, high, medium, low, info or none.
	Severity string `json:"severity"`
	// PriorityClass is P0..P3, or "" when not classified.
	PriorityClass string `json:"priority_class,omitempty"`
	// KEV: listed as known exploited.
	KEV bool `json:"kev"`
	// EPSS is the exploit prediction score (0..1), nil when unknown.
	EPSS *float64 `json:"epss,omitempty"`
	// ExploitValidated: a validation proved the issue exploitable.
	ExploitValidated bool `json:"exploit_validated"`
	// CrownJewel / InternetExposed describe the finding's asset.
	CrownJewel      bool `json:"crown_jewel"`
	InternetExposed bool `json:"internet_exposed"`
}

// PlatformEPSSThreshold is the EPSS score from which a finding is in the
// high class. An organization may only lower it.
const PlatformEPSSThreshold = 0.5

// MinEPSSThreshold bounds how low an organization may set the threshold.
const MinEPSSThreshold = 0.01

// Reason codes explain a class or a tier (stable, shown by the web).
const (
	ReasonSeverityCritical = "severity_critical"
	ReasonSeverityHigh     = "severity_high"
	ReasonPriorityP0       = "priority_p0"
	ReasonPriorityP1       = "priority_p1"
	ReasonKEV              = "kev"
	ReasonEPSS             = "epss_at_or_above_threshold"
	ReasonExploitValidated = "exploit_validated"
	ReasonCrownJewel       = "crown_jewel"
	ReasonInternetExposed  = "internet_exposed"
)

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// priorityRank: P0 is the most urgent (4), no priority 0.
func priorityRank(p string) int {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "P0":
		return 4
	case "P1":
		return 3
	case "P2":
		return 2
	case "P3":
		return 1
	}
	return 0
}

func epssAtOrAbove(e *float64, threshold float64) bool {
	return e != nil && *e >= threshold
}

// ClassOf is the risk class of a finding with these facts for a request of
// kind k, and the reasons for it.
//
//	critical: severity critical, priority P0, or KEV
//	high:     severity high, priority P1, a validated exploit, or EPSS at
//	          or above the threshold
//	standard: anything else
//
// For an accepted risk, a crown-jewel or internet-exposed asset raises the
// class by one step.
func ClassOf(k Kind, f Facts, epssThreshold float64) (Class, []string) {
	if epssThreshold <= 0 || epssThreshold > PlatformEPSSThreshold {
		epssThreshold = PlatformEPSSThreshold
	}
	var reasons []string
	class := ClassStandard
	add := func(c Class, reason string) {
		class = MaxClass(class, c)
		reasons = append(reasons, reason)
	}
	switch {
	case severityRank(f.Severity) == 4:
		add(ClassCritical, ReasonSeverityCritical)
	case severityRank(f.Severity) == 3:
		add(ClassHigh, ReasonSeverityHigh)
	}
	switch priorityRank(f.PriorityClass) {
	case 4:
		add(ClassCritical, ReasonPriorityP0)
	case 3:
		add(ClassHigh, ReasonPriorityP1)
	}
	if f.KEV {
		add(ClassCritical, ReasonKEV)
	}
	if f.ExploitValidated {
		add(ClassHigh, ReasonExploitValidated)
	}
	if epssAtOrAbove(f.EPSS, epssThreshold) {
		add(ClassHigh, ReasonEPSS)
	}
	if k.IsAcceptance() && (f.CrownJewel || f.InternetExposed) {
		class = class.raised()
		if f.CrownJewel {
			reasons = append(reasons, ReasonCrownJewel)
		}
		if f.InternetExposed {
			reasons = append(reasons, ReasonInternetExposed)
		}
	}
	return class, reasons
}

// MaterialForFalsePositive reports whether a false positive on a finding
// with these facts always needs a second person under the
// high_and_above level: its class is above standard, or its asset is a
// crown jewel or internet exposed.
func MaterialForFalsePositive(f Facts, epssThreshold float64) bool {
	c, _ := ClassOf(KindFalsePositive, f, epssThreshold)
	return c != ClassStandard || f.CrownJewel || f.InternetExposed
}

// PlatformAcceptanceCap is the longest a risk on a finding of this priority
// may stay accepted: P0 or KEV 30 days, P1 90, P2 180, P3 (and no priority)
// 365.
func PlatformAcceptanceCap(priorityClass string, kev bool) time.Duration {
	const day = 24 * time.Hour
	switch {
	case kev || priorityRank(priorityClass) == 4:
		return 30 * day
	case priorityRank(priorityClass) == 3:
		return 90 * day
	case priorityRank(priorityClass) == 2:
		return 180 * day
	default:
		return 365 * day
	}
}

// WorstFacts combines the facts of several findings into the facts of the
// worst case (a rule or a group decides all of them): the highest severity
// and priority, and any flag set on any of them; the highest EPSS.
func WorstFacts(all []Facts) Facts {
	var w Facts
	for _, f := range all {
		if severityRank(f.Severity) > severityRank(w.Severity) || w.Severity == "" {
			w.Severity = f.Severity
		}
		if priorityRank(f.PriorityClass) > priorityRank(w.PriorityClass) {
			w.PriorityClass = f.PriorityClass
		}
		w.KEV = w.KEV || f.KEV
		w.ExploitValidated = w.ExploitValidated || f.ExploitValidated
		w.CrownJewel = w.CrownJewel || f.CrownJewel
		w.InternetExposed = w.InternetExposed || f.InternetExposed
		if f.EPSS != nil && (w.EPSS == nil || *f.EPSS > *w.EPSS) {
			e := *f.EPSS
			w.EPSS = &e
		}
	}
	return w
}

// Signal is one material change of a finding's facts.
type Signal string

const (
	SignalSeverityRaised   Signal = "severity_raised"
	SignalPriorityRaised   Signal = "priority_raised"
	SignalKEVAdded         Signal = "kev_added"
	SignalEPSSCrossed      Signal = "epss_crossed"
	SignalExploitValidated Signal = "exploit_validated"
	SignalExposureRaised   Signal = "exposure_raised"
)

// Signals lists the material changes from before to after: severity or
// priority up, KEV added, EPSS reaching the threshold, a newly validated
// exploit, the asset newly internet exposed or a crown jewel.
func Signals(before, after Facts, epssThreshold float64) []Signal {
	if epssThreshold <= 0 || epssThreshold > PlatformEPSSThreshold {
		epssThreshold = PlatformEPSSThreshold
	}
	var out []Signal
	if severityRank(after.Severity) > severityRank(before.Severity) {
		out = append(out, SignalSeverityRaised)
	}
	if priorityRank(after.PriorityClass) > priorityRank(before.PriorityClass) {
		out = append(out, SignalPriorityRaised)
	}
	if after.KEV && !before.KEV {
		out = append(out, SignalKEVAdded)
	}
	if epssAtOrAbove(after.EPSS, epssThreshold) && !epssAtOrAbove(before.EPSS, epssThreshold) {
		out = append(out, SignalEPSSCrossed)
	}
	if after.ExploitValidated && !before.ExploitValidated {
		out = append(out, SignalExploitValidated)
	}
	if (after.InternetExposed && !before.InternetExposed) || (after.CrownJewel && !before.CrownJewel) {
		out = append(out, SignalExposureRaised)
	}
	return out
}
