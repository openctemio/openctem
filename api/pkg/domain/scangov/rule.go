package scangov

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits of the rule set (stored in the organization's settings).
const (
	MaxRules            = 50
	MaxRuleNameLen      = 120
	MaxListItems        = 50
	MaxItemLen          = 100
	MaxTicketPatternLen = 200
	MaxValidityDays     = 365
	MaxApprovals        = 2
	// MaxNoteLen bounds a reason or note.
	MaxNoteLen = 1000
	// DefaultPendingDays is how long a request waits for approvers.
	DefaultPendingDays = 14
	// MaxPendingDays bounds the organization's pending expiry.
	MaxPendingDays = 90
)

// Validity says how long an approval lets a scan definition run.
type Validity string

// Validities, from the shortest to the longest.
const (
	// ValidityRun: the next run only.
	ValidityRun Validity = "run"
	// ValidityDays: runs for N days from the approval (and while the
	// definition is unchanged).
	ValidityDays Validity = "days"
	// ValidityDefinition: every run until the definition changes (default).
	ValidityDefinition Validity = "definition"
)

// Conditions decide which scans a rule catches: every condition set must
// hold (AND). A rule with no condition catches every scan.
type Conditions struct {
	// MinIntensity: the scan probes at this intensity or above (passive,
	// active, intrusive).
	MinIntensity string `json:"min_intensity,omitempty"`
	// Tools: the scan runs any of these tools (the scanner, or a workflow
	// step's tool), case-insensitive.
	Tools []string `json:"tools,omitempty"`
	// AssetTags: any target asset carries any of these tags.
	AssetTags []string `json:"asset_tags,omitempty"`
	// MinCriticality: any target asset is at least this critical (low,
	// medium, high, critical).
	MinCriticality string `json:"min_criticality,omitempty"`
	// CrownJewel: any target asset is a crown jewel.
	CrownJewel bool `json:"crown_jewel,omitempty"`
	// DynamicSelectors: the targets use a wildcard domain or a CIDR, which
	// each run resolves again.
	DynamicSelectors bool `json:"dynamic_selectors,omitempty"`
	// TargetsOver: the scan names more than this many targets (direct
	// targets and asset-group members). 0 = not used.
	TargetsOver int `json:"targets_over,omitempty"`
	// CIDRWiderThan: a CIDR target is wider than this prefix length (an
	// IPv4 /16 is wider than /24). 0 = not used.
	CIDRWiderThan int `json:"cidr_wider_than,omitempty"`
	// Recurring: the scan runs on a schedule (not once, not manual).
	Recurring bool `json:"recurring,omitempty"`
	// SensorPlacement: "platform" (the platform's sensors may run it) or
	// "tenant" (only the organization's own sensors).
	SensorPlacement string `json:"sensor_placement,omitempty"`
	// ZoneIDs: the scan is pinned to any of these scan zones.
	ZoneIDs []string `json:"zone_ids,omitempty"`
	// RequesterRoles: the requester holds any of these roles (owner,
	// admin, member, viewer, or a custom role id).
	RequesterRoles []string `json:"requester_roles,omitempty"`
	// RequesterGroupIDs: the requester belongs to any of these groups.
	RequesterGroupIDs []string `json:"requester_group_ids,omitempty"`
	// Origins: the scan is asked for or started through any of these
	// (ui, api_key, service_account, mcp, ci, system).
	Origins []string `json:"origins,omitempty"`
	// TrustedServiceAccountIDs: the organization's service accounts this
	// rule never catches (only service accounts: a person's id here exempts
	// nobody).
	TrustedServiceAccountIDs []string `json:"trusted_service_account_ids,omitempty"`
	// Hours: a weekly schedule; the rule catches scans outside it (or
	// inside it, Match "inside"), at the time of the run.
	Hours *Hours `json:"hours,omitempty"`
}

// Requirement is what a caught scan needs before it runs.
type Requirement struct {
	// Approvals: distinct approvers, never the requester (1 or 2; Strict
	// raises it to 2).
	Approvals int `json:"approvals"`
	// ApproverRoles limits who approves to these organization roles
	// (owner, admin). Empty with ApproverUserIDs empty: anyone who holds
	// scans:approve.
	ApproverRoles []string `json:"approver_roles,omitempty"`
	// ApproverUserIDs names approvers (they must hold scans:approve). A
	// person counts when their role or their id is listed.
	ApproverUserIDs []string `json:"approver_user_ids,omitempty"`
	// RequireJustification: the request must say why.
	RequireJustification bool `json:"require_justification,omitempty"`
	// RequireTicket: the request must carry a change ticket id, matching
	// TicketPattern when set (an RE2 expression, anchored).
	RequireTicket bool   `json:"require_ticket,omitempty"`
	TicketPattern string `json:"ticket_pattern,omitempty"`
	// Validity of the approval; ValidityDays uses ValidityDays.
	Validity     Validity `json:"validity,omitempty"`
	ValidityDays int      `json:"validity_days,omitempty"`
}

// Rule is one approval rule: conditions → requirement. Monitor records that
// a scan would need approval without blocking it.
type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Enabled     bool        `json:"enabled"`
	Monitor     bool        `json:"monitor,omitempty"`
	Conditions  Conditions  `json:"conditions"`
	Requirement Requirement `json:"requirement"`
}

// Sensor placements a rule may name.
const (
	PlacementPlatform = "platform"
	PlacementTenant   = "tenant"
)

// Approver roles a rule may name.
const (
	RoleOwner = "owner"
	RoleAdmin = "admin"
)

// Criticality ranks (asset criticality values).
var criticalityRank = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// CriticalityRank is c's rank (0 for none or unknown).
func CriticalityRank(c string) int { return criticalityRank[strings.ToLower(strings.TrimSpace(c))] }

// IntensityTier is the tier of an intensity name (passive 0, active 1,
// intrusive 2), -1 when unknown.
func IntensityTier(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passive":
		return 0
	case "active":
		return 1
	case "intrusive":
		return 2
	}
	return -1
}

// IntensityName is the name of tier t.
func IntensityName(t int) string {
	switch {
	case t <= 0:
		return "passive"
	case t == 1:
		return "active"
	}
	return "intrusive"
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{shared.ErrValidation}, args...)...)
}

// Normalize trims and validates the rule set, assigns ids to new rules and
// returns the cleaned copy. Ids must be unique.
func Normalize(rules []Rule) ([]Rule, error) {
	if len(rules) > MaxRules {
		return nil, invalid("at most %d rules", MaxRules)
	}
	out := make([]Rule, 0, len(rules))
	seen := map[string]bool{}
	for i, r := range rules {
		n, err := r.normalized()
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if seen[n.ID] {
			return nil, invalid("rule %d: duplicate id", i+1)
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out, nil
}

func (r Rule) normalized() (Rule, error) {
	r.ID = strings.ToLower(strings.TrimSpace(r.ID))
	if r.ID == "" {
		r.ID = uuid.NewString()
	} else if u, err := uuid.Parse(r.ID); err != nil || u.String() != r.ID {
		return r, invalid("id must be a UUID")
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > MaxRuleNameLen || strings.ContainsAny(r.Name, "\r\n") {
		return r, invalid("name is required (one line, at most %d characters)", MaxRuleNameLen)
	}
	var err error
	if r.Conditions, err = r.Conditions.normalized(); err != nil {
		return r, err
	}
	if r.Requirement, err = r.Requirement.normalized(); err != nil {
		return r, err
	}
	return r, nil
}

func cleanList(in []string, lower bool, what string) ([]string, error) {
	if len(in) > MaxListItems {
		return nil, invalid("%s: at most %d items", what, MaxListItems)
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		if v == "" {
			continue
		}
		if len(v) > MaxItemLen || strings.ContainsAny(v, "\r\n") {
			return nil, invalid("%s: items are one line of at most %d characters", what, MaxItemLen)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func isUUID(v string) bool {
	u, err := uuid.Parse(v)
	return err == nil && u.String() == v
}

func cleanUUIDs(in []string, what string) ([]string, error) {
	out, err := cleanList(in, true, what)
	if err != nil {
		return nil, err
	}
	for _, v := range out {
		if u, err := uuid.Parse(v); err != nil || u.String() != v {
			return nil, invalid("%s: %q is not a UUID", what, v)
		}
	}
	return out, nil
}

func (c Conditions) normalized() (Conditions, error) {
	var err error
	if c.MinIntensity = strings.ToLower(strings.TrimSpace(c.MinIntensity)); c.MinIntensity != "" && IntensityTier(c.MinIntensity) < 0 {
		return c, invalid("min_intensity must be passive, active or intrusive")
	}
	if c.MinCriticality = strings.ToLower(strings.TrimSpace(c.MinCriticality)); c.MinCriticality != "" && CriticalityRank(c.MinCriticality) < 1 {
		return c, invalid("min_criticality must be low, medium, high or critical")
	}
	if c.Tools, err = cleanList(c.Tools, true, "tools"); err != nil {
		return c, err
	}
	if c.AssetTags, err = cleanList(c.AssetTags, false, "asset_tags"); err != nil {
		return c, err
	}
	if c.ZoneIDs, err = cleanUUIDs(c.ZoneIDs, "zone_ids"); err != nil {
		return c, err
	}
	if c.TargetsOver < 0 || c.TargetsOver > 1_000_000 {
		return c, invalid("targets_over must be 0 to 1000000")
	}
	if c.CIDRWiderThan < 0 || c.CIDRWiderThan > 128 {
		return c, invalid("cidr_wider_than must be a prefix length (0 to 128)")
	}
	switch c.SensorPlacement = strings.ToLower(strings.TrimSpace(c.SensorPlacement)); c.SensorPlacement {
	case "", PlacementPlatform, PlacementTenant:
	default:
		return c, invalid("sensor_placement must be platform or tenant")
	}
	return c.normalizedRequester()
}

func (q Requirement) normalized() (Requirement, error) {
	var err error
	if q.Approvals < 1 || q.Approvals > MaxApprovals {
		return q, invalid("approvals must be 1 or 2")
	}
	if q.ApproverRoles, err = cleanList(q.ApproverRoles, true, "approver_roles"); err != nil {
		return q, err
	}
	for _, r := range q.ApproverRoles {
		if r != RoleOwner && r != RoleAdmin {
			return q, invalid("approver_roles may name owner and admin")
		}
	}
	if q.ApproverUserIDs, err = cleanUUIDs(q.ApproverUserIDs, "approver_user_ids"); err != nil {
		return q, err
	}
	q.TicketPattern = strings.TrimSpace(q.TicketPattern)
	if len(q.TicketPattern) > MaxTicketPatternLen {
		return q, invalid("ticket_pattern: at most %d characters", MaxTicketPatternLen)
	}
	if q.TicketPattern != "" {
		if _, err := compileTicket(q.TicketPattern); err != nil {
			return q, invalid("ticket_pattern is not a valid expression")
		}
		q.RequireTicket = true
	}
	switch q.Validity {
	case "":
		q.Validity = ValidityDefinition
	case ValidityRun, ValidityDefinition:
	case ValidityDays:
		if q.ValidityDays < 1 || q.ValidityDays > MaxValidityDays {
			return q, invalid("validity_days must be 1 to %d", MaxValidityDays)
		}
	default:
		return q, invalid("validity must be run, days or definition")
	}
	if q.Validity != ValidityDays {
		q.ValidityDays = 0
	}
	return q, nil
}

// compileTicket compiles an anchored ticket pattern (RE2: linear time, no
// backtracking, so a pattern cannot stall the server).
func compileTicket(p string) (*regexp.Regexp, error) {
	return regexp.Compile(`^(?:` + p + `)$`)
}

// TicketMatches reports whether ticket matches pattern ("" matches any
// non-empty ticket).
func TicketMatches(pattern, ticket string) bool {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return false
	}
	if pattern == "" {
		return true
	}
	re, err := compileTicket(pattern)
	return err == nil && re.MatchString(ticket)
}
