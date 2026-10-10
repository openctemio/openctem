package scangov

import (
	"slices"
	"strings"
)

// Facts are what the rules read about a scan definition. The application
// computes them from the definition and the inventory; every field is the
// organization's own data.
type Facts struct {
	// IntensityTier: 0 passive, 1 active, 2 intrusive.
	IntensityTier int `json:"intensity_tier"`
	// Tools the scan runs (lower case).
	Tools []string `json:"tools,omitempty"`
	// TargetCount: direct targets plus asset-group members.
	TargetCount int `json:"target_count"`
	// DynamicSelectors: a wildcard domain or a CIDR among the targets.
	DynamicSelectors bool `json:"dynamic_selectors,omitempty"`
	// WidestCIDRPrefix: the smallest prefix length among CIDR targets
	// (-1: none).
	WidestCIDRPrefix int `json:"widest_cidr_prefix"`
	// AssetTags: the tags of the known target assets.
	AssetTags []string `json:"asset_tags,omitempty"`
	// MaxCriticality among the known target assets.
	MaxCriticality string `json:"max_criticality,omitempty"`
	// CrownJewel: a known target asset is a crown jewel.
	CrownJewel bool `json:"crown_jewel,omitempty"`
	// Recurring: the scan runs on a schedule.
	Recurring bool `json:"recurring,omitempty"`
	// SensorPlacement: platform, tenant or auto (auto may use platform
	// sensors).
	SensorPlacement string `json:"sensor_placement,omitempty"`
	// ZoneID the scan is pinned to ("" automatic).
	ZoneID string `json:"zone_id,omitempty"`
}

// Matches reports whether facts f satisfy conditions c.
func (c Conditions) Matches(f Facts) bool {
	if c.MinIntensity != "" && f.IntensityTier < IntensityTier(c.MinIntensity) {
		return false
	}
	if len(c.Tools) > 0 && !anyIn(c.Tools, f.Tools, true) {
		return false
	}
	if len(c.AssetTags) > 0 && !anyIn(c.AssetTags, f.AssetTags, true) {
		return false
	}
	if c.MinCriticality != "" && CriticalityRank(f.MaxCriticality) < CriticalityRank(c.MinCriticality) {
		return false
	}
	if c.CrownJewel && !f.CrownJewel {
		return false
	}
	if c.DynamicSelectors && !f.DynamicSelectors {
		return false
	}
	if c.TargetsOver > 0 && f.TargetCount <= c.TargetsOver {
		return false
	}
	if c.CIDRWiderThan > 0 && (f.WidestCIDRPrefix < 0 || f.WidestCIDRPrefix >= c.CIDRWiderThan) {
		return false
	}
	if c.Recurring && !f.Recurring {
		return false
	}
	switch c.SensorPlacement {
	case PlacementPlatform:
		if f.SensorPlacement == PlacementTenant {
			return false
		}
	case PlacementTenant:
		if f.SensorPlacement != PlacementTenant {
			return false
		}
	}
	if len(c.ZoneIDs) > 0 && !slices.Contains(c.ZoneIDs, strings.ToLower(f.ZoneID)) {
		return false
	}
	return true
}

func anyIn(want, have []string, fold bool) bool {
	for _, w := range want {
		for _, h := range have {
			if w == h || (fold && strings.EqualFold(w, h)) {
				return true
			}
		}
	}
	return false
}

// MatchedRule is a rule that caught a scan, as shown to requesters and
// approvers.
type MatchedRule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Monitor     bool        `json:"monitor,omitempty"`
	Requirement Requirement `json:"requirement"`
}

// Evaluation is the outcome of the rules for one scan definition.
type Evaluation struct {
	// Mode in force.
	Mode Mode `json:"mode"`
	// Required: the scan needs an approval before it runs.
	Required bool `json:"required"`
	// Matched: the blocking rules that caught the scan, in rule order.
	Matched []MatchedRule `json:"matched,omitempty"`
	// Monitored: the monitor-mode rules that caught it (they do not block).
	Monitored []MatchedRule `json:"monitored,omitempty"`
	// Decisive is the id of the rule whose approvers apply: the first
	// matched rule with the most approvals.
	Decisive string `json:"decisive,omitempty"`
	// Requirement merged from the matched rules: the most approvals (two
	// in Strict), justification or ticket when any rule asks, every ticket
	// pattern, the shortest validity, the decisive rule's approvers.
	Approvals            int      `json:"approvals,omitempty"`
	ApproverRoles        []string `json:"approver_roles,omitempty"`
	ApproverUserIDs      []string `json:"approver_user_ids,omitempty"`
	RequireJustification bool     `json:"require_justification,omitempty"`
	RequireTicket        bool     `json:"require_ticket,omitempty"`
	TicketPatterns       []string `json:"ticket_patterns,omitempty"`
	Validity             Validity `json:"validity,omitempty"`
	ValidityDays         int      `json:"validity_days,omitempty"`
}

// Evaluate applies rules under mode m to facts f. Off never requires
// anything. Disabled rules are skipped.
func Evaluate(m Mode, rules []Rule, f Facts) Evaluation {
	ev := Evaluation{Mode: m.Normalized()}
	if ev.Mode == ModeOff {
		return ev
	}
	var decisive *Rule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || !r.Conditions.Matches(f) {
			continue
		}
		mr := MatchedRule{ID: r.ID, Name: r.Name, Monitor: r.Monitor, Requirement: r.Requirement}
		if r.Monitor {
			ev.Monitored = append(ev.Monitored, mr)
			continue
		}
		ev.Matched = append(ev.Matched, mr)
		if decisive == nil || r.Requirement.Approvals > decisive.Requirement.Approvals {
			decisive = r
		}
	}
	if decisive == nil {
		return ev
	}
	ev.Required = true
	ev.Decisive = decisive.ID
	ev.Approvals = decisive.Requirement.Approvals
	ev.ApproverRoles = slices.Clone(decisive.Requirement.ApproverRoles)
	ev.ApproverUserIDs = slices.Clone(decisive.Requirement.ApproverUserIDs)
	ev.Validity = ValidityDefinition
	for _, mr := range ev.Matched {
		q := mr.Requirement
		ev.RequireJustification = ev.RequireJustification || q.RequireJustification
		if q.RequireTicket {
			ev.RequireTicket = true
			if q.TicketPattern != "" && !slices.Contains(ev.TicketPatterns, q.TicketPattern) {
				ev.TicketPatterns = append(ev.TicketPatterns, q.TicketPattern)
			}
		}
		ev.Validity, ev.ValidityDays = shorterValidity(ev.Validity, ev.ValidityDays, q.Validity, q.ValidityDays)
	}
	if ev.Mode == ModeStrict {
		ev.Approvals = max(ev.Approvals, MaxApprovals)
		ev.RequireJustification = true
	}
	return ev
}

func validityRank(v Validity) int {
	switch v {
	case ValidityRun:
		return 0
	case ValidityDays:
		return 1
	}
	return 2
}

func shorterValidity(a Validity, ad int, b Validity, bd int) (Validity, int) {
	if b == "" {
		b = ValidityDefinition
	}
	switch {
	case validityRank(b) < validityRank(a):
		return b, bd
	case a == ValidityDays && b == ValidityDays && bd < ad:
		return a, bd
	}
	return a, ad
}

// CheckEvidence reports what the request lacks for ev, "" when nothing.
func (ev Evaluation) CheckEvidence(justification, ticket string) string {
	if ev.RequireJustification && strings.TrimSpace(justification) == "" {
		return "a justification is required"
	}
	if ev.RequireTicket {
		if strings.TrimSpace(ticket) == "" {
			return "a change ticket id is required"
		}
		for _, p := range ev.TicketPatterns {
			if !TicketMatches(p, ticket) {
				return "the change ticket id does not have the required format"
			}
		}
	}
	return ""
}

// Preset names.
const (
	PresetLight    = "light"
	PresetStandard = "standard"
	PresetStrict   = "strict"
)

// Preset returns the rules of a named preset (fresh ids each call), or nil
// for an unknown name. Light: intrusive scans. Standard: Light plus active
// scans on production-tagged, high-criticality or crown-jewel assets, and
// wide scans. Strict: Standard with two approvers and a change ticket.
func Preset(name string) []Rule {
	intrusive := Rule{Name: "Intrusive scans", Enabled: true,
		Conditions:  Conditions{MinIntensity: "intrusive"},
		Requirement: Requirement{Approvals: 1, RequireJustification: true}}
	production := Rule{Name: "Active scans on production assets", Enabled: true,
		Conditions:  Conditions{MinIntensity: "active", AssetTags: []string{"production", "prod"}},
		Requirement: Requirement{Approvals: 1}}
	critical := Rule{Name: "Active scans on high-criticality assets", Enabled: true,
		Conditions:  Conditions{MinIntensity: "active", MinCriticality: "high"},
		Requirement: Requirement{Approvals: 1}}
	crown := Rule{Name: "Active scans on crown jewels", Enabled: true,
		Conditions:  Conditions{MinIntensity: "active", CrownJewel: true},
		Requirement: Requirement{Approvals: 1}}
	wide := Rule{Name: "Wide scans (more than 500 targets)", Enabled: true,
		Conditions:  Conditions{MinIntensity: "active", TargetsOver: 500},
		Requirement: Requirement{Approvals: 1}}
	var out []Rule
	switch name {
	case PresetLight:
		out = []Rule{intrusive}
	case PresetStandard:
		out = []Rule{intrusive, production, critical, crown, wide}
	case PresetStrict:
		out = []Rule{intrusive, production, critical, crown, wide}
		for i := range out {
			out[i].Requirement.Approvals = 2
			out[i].Requirement.RequireJustification = true
			out[i].Requirement.RequireTicket = true
		}
	default:
		return nil
	}
	n, _ := Normalize(out)
	return n
}
