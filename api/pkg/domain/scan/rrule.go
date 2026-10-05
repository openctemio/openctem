package scan

// RRULE schedules (RFC-046 D11, §6.1). See docs/rfcs/RFC-046-scans-redesign.md.

import (
	"fmt"
	"strings"
	"time"

	"github.com/teambition/rrule-go"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxRRuleLength bounds a stored recurrence rule.
const MaxRRuleLength = 500

// rruleAnchor is the fixed start every rule is evaluated from (a Monday at
// midnight in the scan timezone), so INTERVAL counts the same way for every
// scan and on every replica, and a rule without BYHOUR/BYMINUTE fires at
// midnight.
func rruleAnchor(loc *time.Location) time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, loc)
}

// parseScheduleRRule parses rule (RRULE parts only, no DTSTART) in loc.
// Refused: an empty or oversized rule, DTSTART or RRULE: prefixes,
// FREQ=SECONDLY, BYSECOND, COUNT (it would count from the fixed anchor),
// and anything rrule-go cannot parse. Seconds are always 0.
func parseScheduleRRule(rule string, loc *time.Location) (*rrule.RRule, error) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return nil, fmt.Errorf("the recurrence rule is empty")
	}
	if len(rule) > MaxRRuleLength {
		return nil, fmt.Errorf("the recurrence rule is longer than %d characters", MaxRRuleLength)
	}
	upper := strings.ToUpper(rule)
	for _, bad := range []string{"DTSTART", "RRULE:", "\n", "\r"} {
		if strings.Contains(upper, bad) {
			return nil, fmt.Errorf("give only the RRULE parts (FREQ=...;...), without %s", strings.TrimSpace(bad))
		}
	}
	for _, part := range strings.Split(upper, ";") {
		key, val, _ := strings.Cut(part, "=")
		switch key {
		case "FREQ":
			if val == "SECONDLY" {
				return nil, fmt.Errorf("FREQ=SECONDLY is not allowed")
			}
		case "BYSECOND":
			return nil, fmt.Errorf("BYSECOND is not allowed; runs start on the minute")
		case "COUNT":
			return nil, fmt.Errorf("COUNT is not allowed; use UNTIL to end a schedule")
		}
	}
	opt, err := rrule.StrToROption(rule)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the recurrence rule: %w", err)
	}
	opt.Dtstart = rruleAnchor(loc)
	opt.Bysecond = []int{0}
	r, err := rrule.NewRRule(*opt)
	if err != nil {
		return nil, fmt.Errorf("invalid recurrence rule: %w", err)
	}
	return r, nil
}

// minRRuleGap is the shortest gap between consecutive occurrences of r over
// the year after now (a yearly rule may only crowd runs in one month), and
// whether r has any occurrence after now. One pass
// (Between), never one After per occurrence: each After walks the rule from
// its anchor.
func minRRuleGap(r *rrule.RRule, now time.Time) (time.Duration, bool) {
	occ := r.Between(now, now.AddDate(1, 0, 1), false)
	if len(occ) == 0 {
		if r.After(now, false).IsZero() {
			return 0, false
		}
		return time.Duration(1<<63 - 1), true // less than once a year
	}
	gap := time.Duration(1<<63 - 1)
	for i := 1; i < len(occ); i++ {
		gap = min(gap, occ[i].Sub(occ[i-1]))
	}
	return gap, true
}

// SetRRuleSchedule makes the scan run on rule, an RFC 5545 recurrence rule
// (RRULE parts, e.g. "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=2;BYMINUTE=30"),
// evaluated in timezone (IANA, default UTC). The rule must parse, have a
// future occurrence and never fire more often than MinScheduleInterval.
func (s *Scan) SetRRuleSchedule(rule, timezone string) error {
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "unknown timezone: "+timezone, shared.ErrValidation)
	}
	rule = strings.ToUpper(strings.TrimSpace(rule))
	r, err := parseScheduleRRule(rule, loc)
	if err != nil {
		return shared.NewDomainError("VALIDATION", err.Error(), shared.ErrValidation)
	}
	gap, future := minRRuleGap(r, time.Now().In(loc))
	if !future {
		return shared.NewDomainError("VALIDATION", "the recurrence rule has no future occurrence", shared.ErrValidation)
	}
	if gap < MinScheduleInterval {
		return shared.NewDomainError("VALIDATION",
			fmt.Sprintf("schedule fires every %s; the minimum interval is %s", gap, MinScheduleInterval),
			shared.ErrValidation)
	}

	s.ScheduleType = ScheduleRRule
	s.ScheduleRRule = rule
	s.ScheduleCron = ""
	s.ScheduleDay = nil
	s.ScheduleTime = nil
	s.ScheduleTimezone = timezone
	s.UpdatedAt = time.Now()
	s.computeNextRunAt()
	return nil
}
