// Package ticketpolicy decides which findings the automatic ticket path files
// as tracker issues on one integration (docs/architecture/ticket-create-policy.md).
//
// The policy is a noise filter, not a security control: it can only hold a
// finding back. Every create it lets through still passes the outbound
// (egress / TLP) gate.
package ticketpolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MaxDailyCap bounds the daily cap (the DB check agrees).
const MaxDailyCap = 10000

// Policy is one integration's "create issues automatically when" rule:
// severity >= MinSeverity OR priority class >= MinPriorityClass OR (KEV and
// AlwaysKEV). A finding must also be open.
type Policy struct {
	MinSeverity      vulnerability.Severity `json:"min_severity"`
	MinPriorityClass string                 `json:"min_priority_class"` // "" = not used
	AlwaysKEV        bool                   `json:"always_kev"`
	DailyCap         int                    `json:"daily_cap"` // 0 = no cap
	// UpdatedAt is zero when the integration has no stored policy (defaults).
	UpdatedAt time.Time  `json:"updated_at,omitzero"`
	UpdatedBy *shared.ID `json:"-"`
}

// Default is the policy of an integration that has none stored.
func Default() Policy {
	return Policy{MinSeverity: vulnerability.SeverityMedium, MinPriorityClass: "P2", AlwaysKEV: true, DailyCap: 200}
}

// severities is the policy scale, most severe first.
var severities = []vulnerability.Severity{
	vulnerability.SeverityCritical, vulnerability.SeverityHigh, vulnerability.SeverityMedium,
	vulnerability.SeverityLow, vulnerability.SeverityInfo,
}

var classes = []string{"P0", "P1", "P2", "P3"}

// Normalize trims and lower/upper-cases the fields.
func (p Policy) Normalize() Policy {
	p.MinSeverity = vulnerability.Severity(strings.ToLower(strings.TrimSpace(string(p.MinSeverity))))
	p.MinPriorityClass = strings.ToUpper(strings.TrimSpace(p.MinPriorityClass))
	return p
}

// Validate reports a shared.ErrValidation for a policy that cannot be stored.
func (p Policy) Validate() error {
	if !slices.Contains(severities, p.MinSeverity) {
		return fmt.Errorf("%w: min_severity must be one of critical, high, medium, low, info", shared.ErrValidation)
	}
	if p.MinPriorityClass != "" && !slices.Contains(classes, p.MinPriorityClass) {
		return fmt.Errorf("%w: min_priority_class must be empty or one of P0, P1, P2, P3", shared.ErrValidation)
	}
	if p.DailyCap < 0 || p.DailyCap > MaxDailyCap {
		return fmt.Errorf("%w: daily_cap must be between 0 and %d", shared.ErrValidation, MaxDailyCap)
	}
	return nil
}

// AllowedSeverities lists the stored severity values that pass on their own.
// "none" is reported inside info, so an info floor lets it through.
func (p Policy) AllowedSeverities() []string {
	out := []string{}
	for _, s := range severities {
		out = append(out, string(s))
		if s == vulnerability.SeverityInfo {
			out = append(out, string(vulnerability.SeverityNone))
		}
		if s == p.MinSeverity {
			break
		}
	}
	return out
}

// AllowedClasses lists the priority classes that pass on their own (none
// when the class floor is not used).
func (p Policy) AllowedClasses() []string {
	if p.MinPriorityClass == "" {
		return nil
	}
	i := slices.Index(classes, p.MinPriorityClass)
	if i < 0 {
		return nil
	}
	return slices.Clone(classes[:i+1])
}

// Signals are the finding facts the policy reads.
type Signals struct {
	Severity      string
	PriorityClass string
	InKEV         bool
	Open          bool
}

// SignalsOf reads the signals of a finding.
func SignalsOf(f *vulnerability.Finding) Signals {
	s := Signals{Severity: string(f.Severity()), InKEV: f.IsInKEV(), Open: f.Status().IsOpen()}
	if c := f.PriorityClass(); c != nil {
		s.PriorityClass = string(*c)
	}
	return s
}

// Verdict is the outcome of one evaluation.
type Verdict struct {
	Pass bool `json:"pass"`
	// Reason is why the finding passes ("severity", "priority_class", "kev")
	// or why it is held ("not_open", "below_threshold").
	Reason string `json:"reason"`
}

// Evaluate applies the policy to one finding's signals.
func (p Policy) Evaluate(s Signals) Verdict {
	if !s.Open {
		return Verdict{Reason: "not_open"}
	}
	sev := strings.ToLower(strings.TrimSpace(s.Severity))
	if slices.Contains(p.AllowedSeverities(), sev) {
		return Verdict{Pass: true, Reason: "severity"}
	}
	if s.PriorityClass != "" && slices.Contains(p.AllowedClasses(), strings.ToUpper(s.PriorityClass)) {
		return Verdict{Pass: true, Reason: "priority_class"}
	}
	if p.AlwaysKEV && s.InKEV {
		return Verdict{Pass: true, Reason: "kev"}
	}
	return Verdict{Reason: ReasonBelowThreshold}
}

// Hold reasons (the DB check agrees).
const (
	ReasonBelowThreshold = "below_threshold"
	ReasonDailyCap       = "daily_cap"
	ReasonCreateFailed   = "create_failed"
)

// Hold is a finding the automatic path held back on one integration.
type Hold struct {
	TenantID      shared.ID `json:"-"`
	IntegrationID shared.ID `json:"integration_id"`
	FindingID     shared.ID `json:"finding_id"`
	Reason        string    `json:"reason"`
	Detail        string    `json:"detail,omitempty"`
	HeldAt        time.Time `json:"held_at"`
	CheckedAt     time.Time `json:"checked_at"`
}

// Candidate is a hold due for re-evaluation, with the finding's signals and
// the integration's policy (Default when none is stored).
type Candidate struct {
	Hold
	Signals Signals
	Linked  bool // the finding already has an active issue on this integration
	Policy  Policy
}

// Stats are the counts shown next to a policy.
type Stats struct {
	HeldByReason map[string]int `json:"held_by_reason"`
	CreatedToday int            `json:"created_today"`
}

// Preview is what a policy would do: over the findings first seen in the
// last 30 days, and over the current holds.
type Preview struct {
	Last30DaysTotal int `json:"last_30_days_total"`
	Last30DaysPass  int `json:"last_30_days_pass"`
	HeldNow         int `json:"held_now"`
	HeldWouldPass   int `json:"held_would_pass"`
}

// Repository stores policies, holds and the daily counter. Every method is
// tenant-scoped except the system-wide due-hold listing and the purge.
type Repository interface {
	Get(ctx context.Context, tenantID, integrationID shared.ID) (Policy, error)
	Save(ctx context.Context, tenantID, integrationID shared.ID, p Policy) (Policy, error)
	Stats(ctx context.Context, tenantID, integrationID shared.ID) (Stats, error)
	Preview(ctx context.Context, tenantID, integrationID shared.ID, p Policy) (Preview, error)

	PutHold(ctx context.Context, h Hold) error
	DeleteHold(ctx context.Context, tenantID, integrationID, findingID shared.ID) error
	DeleteFindingHolds(ctx context.Context, tenantID, findingID shared.ID) error
	ListFindingHolds(ctx context.Context, tenantID, findingID shared.ID) ([]Hold, error)
	// DueHolds lists holds to re-check across tenants: the finding changed
	// since the last check, a capped hold on a new UTC day, or a failed
	// create older than retryAfter. Highest severity first.
	DueHolds(ctx context.Context, limit int, retryAfter time.Duration) ([]Candidate, error)

	// Reserve takes one slot of today's cap; false when the cap is reached.
	// A cap of 0 always succeeds and counts nothing.
	Reserve(ctx context.Context, tenantID, integrationID shared.ID, dailyCap int) (bool, error)
	// Release gives a reserved slot back (the create failed).
	Release(ctx context.Context, tenantID, integrationID shared.ID) error
	PurgeDaily(ctx context.Context, olderThan time.Duration) (int64, error)
}
