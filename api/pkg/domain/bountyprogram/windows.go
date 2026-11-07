package bountyprogram

// Testing windows and the rules a job carries (RFC-065 §12). When testing is
// allowed is decided with every other scan window by the scan window
// evaluator (RFC-067; internal/app/scanwindow.ProgramSource).

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanident"
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

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// Errors of the rules a job carries.
var (
	ErrRulesConflict = shared.NewDomainError("PROGRAM_RULES_CONFLICT",
		"the targets belong to programs whose rules conflict (headers or User-Agent); scan one program at a time", shared.ErrValidation)
)

// JobRules are the rules a job carries: the union of the rules of the
// programs that cover its targets.
type JobRules struct {
	Headers map[string]string
	// UserAgent or UserAgents is the programs' User-Agent setting (one
	// value or a rotation list; UserAgentConfig reads either).
	UserAgent  string
	UserAgents []string
	// IdentificationRequired: any covering program requires identification.
	IdentificationRequired bool
	// RateLimit is the smallest program rate (requests per second; 0 none).
	RateLimit int
	// Programs names the programs (for logs).
	Programs []string
	// Forbidden is every technique any covering program forbids.
	Forbidden []string
}

// UserAgentConfig is the User-Agent setting the job carries: the list,
// else the single value, else none.
func (r *JobRules) UserAgentConfig() []string {
	if r == nil {
		return nil
	}
	return scanident.UserAgentConfig(r.UserAgent, r.UserAgents)
}

// SetsIdentity reports whether the rules put headers or a User-Agent on the
// job (the sensor must report sensor.CapabilityHTTPIdentity).
func (r *JobRules) SetsIdentity() bool {
	return r != nil && (len(r.Headers) > 0 || r.UserAgent != "" || len(r.UserAgents) > 0)
}

// EnumerationRefusal is why a job that enumerates (guesses names or paths:
// any enumerate.* capability, a brute force) may not run on targets the
// rules cover: a program forbids brute force or automated scanning. "" when
// it may. A nil receiver allows everything.
func (r *JobRules) EnumerationRefusal() string {
	if r == nil {
		return ""
	}
	for _, t := range []string{ForbidBruteforce, ForbidAutomatedScanning} {
		if slices.Contains(r.Forbidden, t) {
			return fmt.Sprintf("a bug bounty program covering these targets forbids %s (%s); enumeration does not run on them",
				strings.ReplaceAll(t, "_", " "), strings.Join(r.Programs, ", "))
		}
	}
	return ""
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
		// One User-Agent setting per job: two programs with different
		// values or lists conflict (a list is never merged).
		if ua := scanident.UserAgentConfig(r.UserAgent, r.UserAgents); len(ua) > 0 {
			if cur := out.UserAgentConfig(); len(cur) > 0 && !slices.Equal(cur, ua) {
				return nil, ErrRulesConflict
			}
			out.UserAgent, out.UserAgents = r.UserAgent, r.UserAgents
		}
		out.IdentificationRequired = out.IdentificationRequired || r.IdentificationRequired
		for _, f := range r.Forbidden {
			if !slices.Contains(out.Forbidden, f) {
				out.Forbidden = append(out.Forbidden, f)
			}
		}
		if r.RateLimitRPS > 0 && (out.RateLimit == 0 || r.RateLimitRPS < out.RateLimit) {
			out.RateLimit = r.RateLimitRPS
		}
	}
	// What the job carries must be what a sensor sends: more headers than
	// one program may require (several programs together), or a value saved
	// before values had to be ASCII, would be refused by the sensor; the
	// job fails here with the reason instead.
	if len(out.Headers) > MaxHeaders {
		return nil, fmt.Errorf("%w: together the programs require %d headers, more than %d", ErrRulesConflict, len(out.Headers), MaxHeaders)
	}
	for name, v := range out.Headers {
		if !printableASCII(v) {
			return nil, fmt.Errorf("%w: the value of header %s is not printable ASCII; edit the program's rules", ErrRulesConflict, name)
		}
	}
	if !printableASCII(out.UserAgent) {
		return nil, fmt.Errorf("%w: the User-Agent is not printable ASCII; edit the program's rules", ErrRulesConflict)
	}
	if err := scanident.CheckUserAgents("", out.UserAgents); err != nil {
		return nil, fmt.Errorf("%w: the User-Agent list is not acceptable; edit the program's rules", ErrRulesConflict)
	}
	return out, nil
}
