package bountyprogram

// Testing windows and the rules a job carries (RFC-065 §12).

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxTestingWindows bounds a program's windows.
const MaxTestingWindows = 14

var (
	windowDays   = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	windowTimeRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// TestingWindow is when a program allows testing: on the given days, from
// start to end (HH:MM, end after start; no overnight window), in an IANA
// time zone.
type TestingWindow struct {
	Days     []string `json:"days"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Timezone string   `json:"timezone"`
}

// Validate checks one window.
func (w TestingWindow) Validate() error {
	if len(w.Days) == 0 || len(w.Days) > 7 {
		return fmt.Errorf("%w: a testing window names 1 to 7 days", shared.ErrValidation)
	}
	for _, d := range w.Days {
		if !slices.Contains(windowDays, strings.ToLower(d)) {
			return fmt.Errorf("%w: %q is not a day (sun, mon, tue, wed, thu, fri, sat)", shared.ErrValidation, clip(d))
		}
	}
	if !windowTimeRE.MatchString(w.Start) || !windowTimeRE.MatchString(w.End) || w.End <= w.Start {
		return fmt.Errorf("%w: a testing window runs from start to a later end, HH:MM (add two windows for one over midnight)", shared.ErrValidation)
	}
	if w.Timezone == "" || len(w.Timezone) > 64 {
		return fmt.Errorf("%w: a testing window names its time zone", shared.ErrValidation)
	}
	if _, err := time.LoadLocation(w.Timezone); err != nil {
		return fmt.Errorf("%w: %q is not a time zone", shared.ErrValidation, clip(w.Timezone))
	}
	return nil
}

// Open reports whether now falls inside the window.
func (w TestingWindow) Open(now time.Time) bool {
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return false
	}
	t := now.In(loc)
	if !slices.Contains(lower(w.Days), windowDays[t.Weekday()]) {
		return false
	}
	hm := t.Format("15:04")
	return hm >= w.Start && hm < w.End
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// TestingOpen reports whether the rules allow testing now: no window means
// any time.
func (r Rules) TestingOpen(now time.Time) bool {
	if len(r.TestingWindows) == 0 {
		return true
	}
	for _, w := range r.TestingWindows {
		if w.Open(now) {
			return true
		}
	}
	return false
}

// Errors of the rules a job carries.
var (
	ErrRulesConflict = shared.NewDomainError("PROGRAM_RULES_CONFLICT",
		"the targets belong to programs whose rules conflict (headers or User-Agent); scan one program at a time", shared.ErrValidation)
	ErrOutsideWindow = shared.NewDomainError("PROGRAM_OUTSIDE_WINDOW",
		"a program of these targets does not allow testing now (testing windows)", shared.ErrValidation)
)

// JobRules are the rules a job carries: the union of the rules of the
// programs that cover its targets.
type JobRules struct {
	Headers   map[string]string
	UserAgent string
	// RateLimit is the smallest program rate (requests per second; 0 none).
	RateLimit int
	// Programs names the programs (for logs).
	Programs []string
}

// MergeJobRules combines the rules of the programs covering one job. A
// header with two values, or two User-Agents, is a conflict; the rate is the
// smallest stated one.
func MergeJobRules(programs []*Program) (*JobRules, error) {
	if len(programs) == 0 {
		return nil, nil
	}
	out := &JobRules{Headers: map[string]string{}}
	seen := map[string]string{} // lower-cased name -> name
	for _, p := range programs {
		r := p.Rules
		out.Programs = append(out.Programs, p.Name)
		for _, h := range r.RequiredHeaders {
			key := strings.ToLower(h.Name)
			if prev, ok := seen[key]; ok {
				if out.Headers[prev] != h.Value {
					return nil, ErrRulesConflict
				}
				continue
			}
			seen[key] = h.Name
			out.Headers[h.Name] = h.Value
		}
		if r.UserAgent != "" {
			if out.UserAgent != "" && out.UserAgent != r.UserAgent {
				return nil, ErrRulesConflict
			}
			out.UserAgent = r.UserAgent
		}
		if r.RateLimitRPS > 0 && (out.RateLimit == 0 || r.RateLimitRPS < out.RateLimit) {
			out.RateLimit = r.RateLimitRPS
		}
	}
	return out, nil
}
