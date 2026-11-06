package scangov

// The rule tester (RFC-073 §4.3): which of the organization's existing scans
// a proposed rule set would catch, before it is saved. It writes nothing,
// reads only the caller's tenant's saved scans (at most MaxTestedScans,
// newest first) and evaluates each as a run its creator starts from
// the console at its next scheduled time (else now).

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxTestedScans bounds one test.
const MaxTestedScans = 200

// ScanLister lists the tenant's saved scans for the tester
// (*scan.Service).
type ScanLister interface {
	GovernanceScans(ctx context.Context, tenantID shared.ID, limit int) ([]*scan.Scan, int, error)
}

// TestedScan is one scan and what the proposed rules ask of it.
type TestedScan struct {
	ScanID     string             `json:"scan_id"`
	Name       string             `json:"name"`
	Evaluation scangov.Evaluation `json:"evaluation"`
	Intensity  string             `json:"intensity"`
	Schedule   string             `json:"schedule_type,omitempty"`
}

// RuleTest is the tester's answer.
type RuleTest struct {
	// Mode the rules were evaluated under: the mode in force, On when the
	// organization is Off (what turning it on would do).
	Mode scangov.Mode `json:"mode"`
	// Tested scans, Caught (would need approval) and Monitored (caught
	// only by monitor rules).
	Tested    int `json:"tested"`
	Caught    int `json:"caught"`
	Monitored int `json:"monitored"`
	// Total scans of the organization; Truncated when more than tested.
	Total     int          `json:"total"`
	Truncated bool         `json:"truncated"`
	Scans     []TestedScan `json:"scans"`
	// PerRule counts the scans each rule catches, by rule id.
	PerRule map[string]int `json:"per_rule"`
}

// SetScanLister wires the scan list the tester reads.
func (s *Service) SetScanLister(l ScanLister) { s.lister = l }

// TestRules evaluates a proposed rule set against the tenant's existing
// scans. The rules are validated as a save would; nothing is written.
func (s *Service) TestRules(ctx context.Context, tenantID shared.ID, proposed []scangov.Rule) (*RuleTest, error) {
	rules, err := scangov.Normalize(proposed)
	if err != nil {
		return nil, err
	}
	if s.scans == nil || s.lister == nil {
		return nil, fmt.Errorf("%w: scans not wired", shared.ErrInternal)
	}
	m, _, _, err := s.modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read scan approval mode: %w", err)
	}
	if m == scangov.ModeOff {
		m = scangov.ModeOn
	}
	scans, total, err := s.lister.GovernanceScans(ctx, tenantID, MaxTestedScans)
	if err != nil {
		return nil, err
	}
	out := &RuleTest{Mode: m, Total: total, Scans: []TestedScan{}, PerRule: map[string]int{}}
	console := scangov.WithOrigin(ctx, scangov.OriginUI)
	now := s.clock()
	for _, sc := range scans {
		if sc == nil || sc.TenantID != tenantID {
			continue // never another tenant's scan, whatever the lister returns
		}
		_, facts, err := s.scans.GovernanceSubjectOf(ctx, sc)
		if err != nil {
			return nil, err
		}
		if facts, err = s.withRequester(console, tenantID, rules, facts, creatorOf(sc), plannedAt(sc, now)); err != nil {
			return nil, err
		}
		ev := scangov.Evaluate(m, rules, facts)
		out.Tested++
		for _, r := range ev.Matched {
			out.PerRule[r.ID]++
		}
		for _, r := range ev.Monitored {
			out.PerRule[r.ID]++
		}
		switch {
		case ev.Required:
			out.Caught++
		case len(ev.Monitored) > 0:
			out.Monitored++
		default:
			continue
		}
		out.Scans = append(out.Scans, TestedScan{ScanID: sc.ID.String(), Name: sc.Name, Evaluation: ev,
			Intensity: scangov.IntensityName(facts.IntensityTier), Schedule: string(sc.ScheduleType)})
	}
	out.Truncated = out.Total > out.Tested
	return out, nil
}
