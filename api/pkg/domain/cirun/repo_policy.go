package cirun

// A repository's own gate file, .openctem.yml
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, G-8). It can only
// make the central policy stricter, and it can ask for exceptions, which
// become pending suppression requests an administrator approves; it never
// lets a finding pass on its own.

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository file bounds.
const (
	MaxRepoBlockRules   = 100
	MaxRepoExceptions   = 20
	MaxRepoExceptionTTL = 90 * 24 * time.Hour
	minExceptionReason  = 10
	maxExceptionReason  = 500
)

// RepoPolicy is the gate part of a repository's .openctem.yml, as the
// runner sends it with the verdict request.
type RepoPolicy struct {
	FailOnSeverity  string          `json:"fail_on_severity,omitempty"`
	NewFindingsOnly *bool           `json:"new_findings_only,omitempty"`
	FailOnKEV       *bool           `json:"fail_on_kev,omitempty"`
	EPSSThreshold   *float64        `json:"epss_threshold,omitempty"`
	BlockRules      []string        `json:"block_rules,omitempty"`
	Exceptions      []RepoException `json:"exceptions,omitempty"`
}

// RepoException asks for one rule (optionally on a path pattern) of the
// repository to be suppressed until a date.
type RepoException struct {
	RuleID  string `json:"rule_id"`
	Path    string `json:"path,omitempty"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"` // YYYY-MM-DD
	// Source says where the request came from (ExceptionSource*); empty is
	// the repository's .openctem.yml. Never read from the file.
	Source string `json:"-"`
}

// Where a repository exception request came from.
const (
	ExceptionSourceRepoFile   = ""
	ExceptionSourceInline     = "inline"
	ExceptionSourceIgnoreFile = "ignore_file"
)

func clean(s string, n int) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > n || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	return s, true
}

// Validate checks the file's values and bounds.
func (rp *RepoPolicy) Validate(now time.Time) error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: .openctem.yml: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	if rp.FailOnSeverity != "" {
		if _, ok := severityRank[rp.FailOnSeverity]; !ok || rp.FailOnSeverity == "info" {
			return invalid("fail_on_severity must be critical, high, medium or low")
		}
	}
	if rp.EPSSThreshold != nil && (*rp.EPSSThreshold < 0 || *rp.EPSSThreshold > 1) {
		return invalid("epss_threshold must be between 0 and 1")
	}
	if len(rp.BlockRules) > MaxRepoBlockRules {
		return invalid("at most %d block_rules", MaxRepoBlockRules)
	}
	for i, r := range rp.BlockRules {
		c, ok := clean(r, maxModeRuleID)
		if !ok || c == "" {
			return invalid("invalid rule id in block_rules")
		}
		rp.BlockRules[i] = c
	}
	if len(rp.Exceptions) > MaxRepoExceptions {
		return invalid("at most %d exceptions", MaxRepoExceptions)
	}
	for i := range rp.Exceptions {
		e := &rp.Exceptions[i]
		var ok bool
		if e.RuleID, ok = clean(e.RuleID, maxModeRuleID); !ok || e.RuleID == "" {
			return invalid("an exception needs a rule_id")
		}
		if e.Path, ok = clean(e.Path, 500); !ok {
			return invalid("invalid exception path")
		}
		if e.Reason, ok = clean(e.Reason, maxExceptionReason); !ok || len([]rune(e.Reason)) < minExceptionReason {
			return invalid("an exception needs a reason of %d to %d characters", minExceptionReason, maxExceptionReason)
		}
		exp, err := time.Parse("2006-01-02", strings.TrimSpace(e.Expires))
		if err != nil || !exp.After(now) || exp.Sub(now) > MaxRepoExceptionTTL+24*time.Hour {
			return invalid("an exception expires on a date (YYYY-MM-DD) within 90 days")
		}
	}
	return nil
}

// Tighten applies a repository file to the effective policy: each value is
// taken only when it is stricter (lower severity threshold, every finding
// instead of new only, KEV failing, lower EPSS threshold), and block_rules
// block those rules whatever mode the policy gave them.
func (p GatePolicy) Tighten(rp *RepoPolicy) GatePolicy {
	if rp == nil {
		return p
	}
	if rp.FailOnSeverity != "" && rank(rp.FailOnSeverity) < rank(p.FailOnSeverity) {
		p.FailOnSeverity = rp.FailOnSeverity
	}
	if rp.NewFindingsOnly != nil && !*rp.NewFindingsOnly {
		p.NewFindingsOnly = false
	}
	if rp.FailOnKEV != nil && *rp.FailOnKEV {
		p.FailOnKEV = true
	}
	if rp.EPSSThreshold != nil && (p.EPSSThreshold == nil || *rp.EPSSThreshold < *p.EPSSThreshold) {
		v := *rp.EPSSThreshold
		p.EPSSThreshold = &v
	}
	if len(rp.BlockRules) > 0 {
		rules := map[string]string{}
		for k, v := range p.Modes.Rules {
			rules[k] = v
		}
		for _, r := range rp.BlockRules {
			rules[r] = FindingModeBlock
		}
		p.Modes.Rules = rules
	}
	return p
}
