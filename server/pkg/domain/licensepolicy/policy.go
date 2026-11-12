// Package licensepolicy is the organization's license policy: which SPDX
// licenses (or license categories) its software may use, which need review
// and which are denied, optionally per dependency scope, and how a
// package's declared licenses (SPDX expressions) are judged against it.
//
// Design: api/docs/rfcs/RFC-070-software-components-inventory.md, "License
// policy"; architecture doc api/docs/architecture/software-components.md.
package licensepolicy

import (
	"errors"
	"fmt"
	"strings"
)

// Action is a policy verdict, ordered allow < review < deny.
type Action string

// Actions.
const (
	ActionAllow  Action = "allow"
	ActionReview Action = "review"
	ActionDeny   Action = "deny"
)

func (a Action) rank() int {
	switch a {
	case ActionAllow:
		return 0
	case ActionReview:
		return 1
	case ActionDeny:
		return 2
	}
	return -1
}

// Categories of the global licenses catalog.
var categories = map[string]bool{
	"permissive": true, "weak_copyleft": true, "copyleft": true, "proprietary": true,
	"public_domain": true, "unknown": true,
}

// Dependency scopes a rule may be limited to (asset_software.dep_scope).
var scopes = map[string]bool{
	"runtime": true, "development": true, "test": true, "optional": true, "build": true, "provided": true,
}

// Bounds.
const (
	MaxRules      = 200
	MaxMatchLen   = 160
	categoryMatch = "category:"
)

// Rule is one line of the policy: a license (an SPDX id, an id WITH an
// exception, or a LicenseRef-) or a category ("category:copyleft"), the
// action, and optionally the dependency scopes it is limited to.
type Rule struct {
	Match  string   `json:"match"`
	Action Action   `json:"action"`
	Scopes []string `json:"scopes,omitempty"`
}

// Policy is the license_policy settings section.
type Policy struct {
	Enabled bool `json:"enabled"`
	// Default is the verdict of a known license no rule matches: allow
	// (default) or review.
	Default Action `json:"default,omitempty"`
	// Unknown is the verdict of a license that is not an SPDX license the
	// catalog knows, or of a package that declares none: review (default)
	// or deny.
	Unknown Action `json:"unknown,omitempty"`
	// ReviewFindings also opens a (medium) finding for review verdicts;
	// deny always opens a (high) finding.
	ReviewFindings bool   `json:"review_findings,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// ErrInvalid is the error of an invalid policy.
var ErrInvalid = errors.New("invalid license policy")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Normalize checks the policy and fills its defaults.
func (p *Policy) Normalize() error {
	if p.Default == "" {
		p.Default = ActionAllow
	}
	if p.Unknown == "" {
		p.Unknown = ActionReview
	}
	if p.Default != ActionAllow && p.Default != ActionReview {
		return invalid("default must be allow or review")
	}
	if p.Unknown != ActionReview && p.Unknown != ActionDeny {
		return invalid("unknown must be review or deny")
	}
	if len(p.Rules) > MaxRules {
		return invalid("at most %d rules", MaxRules)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.Match = strings.TrimSpace(r.Match)
		if r.Action.rank() < 0 {
			return invalid("rule %d: action must be allow, review or deny", i+1)
		}
		if len(r.Match) == 0 || len(r.Match) > MaxMatchLen {
			return invalid("rule %d: match is empty or longer than %d characters", i+1, MaxMatchLen)
		}
		if c, ok := strings.CutPrefix(strings.ToLower(r.Match), categoryMatch); ok {
			if !categories[c] {
				return invalid("rule %d: unknown category %q", i+1, c)
			}
			r.Match = categoryMatch + c
		} else if !validLicenseMatch(r.Match) {
			return invalid("rule %d: match must be an SPDX license id (optionally WITH an exception) or category:<name>", i+1)
		}
		seen := map[string]bool{}
		clean := r.Scopes[:0]
		for _, s := range r.Scopes {
			s = strings.ToLower(strings.TrimSpace(s))
			if !scopes[s] {
				return invalid("rule %d: unknown scope %q", i+1, s)
			}
			if !seen[s] {
				seen[s] = true
				clean = append(clean, s)
			}
		}
		r.Scopes = clean
		if len(r.Scopes) == 0 {
			r.Scopes = nil
		}
	}
	return nil
}

// validLicenseMatch accepts "ID" or "ID WITH EXCEPTION".
func validLicenseMatch(s string) bool {
	parts := strings.Fields(s)
	switch len(parts) {
	case 1:
		return isLicenseID(parts[0])
	case 3:
		return strings.EqualFold(parts[1], "WITH") && isLicenseID(parts[0]) && isLicenseID(parts[2])
	}
	return false
}

func isLicenseID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+' || r == ':'
		if !ok {
			return false
		}
	}
	return !strings.EqualFold(s, "AND") && !strings.EqualFold(s, "OR") && !strings.EqualFold(s, "WITH")
}

// Verdict is the judgement of a package's licenses.
type Verdict struct {
	Action Action
	// Rule names what decided it: the rule's match, "default" or "unknown".
	Rule string
}

// Catalog maps a lower-case SPDX id to its category (the global licenses
// table). An id it does not hold is unknown.
type Catalog map[string]string

// Evaluate judges a package's declared licenses (each an SPDX id or
// expression) used in dependency scope depScope ("" counts as runtime).
// Several declared licenses must all be acceptable (AND); in an expression,
// OR takes the most permissive choice and AND the strictest term.
func (p *Policy) Evaluate(licenses []string, depScope string, cat Catalog) Verdict {
	if depScope == "" {
		depScope = "runtime"
	}
	if len(licenses) == 0 {
		return Verdict{Action: p.unknown(), Rule: "unknown"}
	}
	var out *Verdict
	for _, l := range licenses {
		v := p.evalExpression(l, depScope, cat)
		if out == nil || v.Action.rank() > out.Action.rank() {
			out = &v
		}
	}
	return *out
}

func (p *Policy) unknown() Action {
	if p.Unknown == "" {
		return ActionReview
	}
	return p.Unknown
}

func (p *Policy) defaultAction() Action {
	if p.Default == "" {
		return ActionAllow
	}
	return p.Default
}

func (p *Policy) evalExpression(expr, depScope string, cat Catalog) Verdict {
	node, err := Parse(expr)
	if err != nil {
		return Verdict{Action: p.unknown(), Rule: "unknown"}
	}
	return p.evalNode(node, depScope, cat)
}

func (p *Policy) evalNode(n *Node, depScope string, cat Catalog) Verdict {
	switch n.Op {
	case OpOr, OpAnd:
		var out *Verdict
		for _, c := range n.Children {
			v := p.evalNode(c, depScope, cat)
			if out == nil || (n.Op == OpOr && v.Action.rank() < out.Action.rank()) ||
				(n.Op == OpAnd && v.Action.rank() > out.Action.rank()) {
				out = &v
			}
		}
		return *out
	}
	return p.evalTerm(n, depScope, cat)
}

// evalTerm judges one license: a rule for the exact id (with its
// exception, then without; with a trailing "+", then without), then a
// category rule, then the unknown or default verdict.
func (p *Policy) evalTerm(n *Node, depScope string, cat Catalog) Verdict {
	candidates := []string{}
	if n.Exception != "" {
		candidates = append(candidates, n.License+" WITH "+n.Exception)
	}
	candidates = append(candidates, n.License)
	if base, ok := strings.CutSuffix(n.License, "+"); ok {
		candidates = append(candidates, base)
	}
	for _, c := range candidates {
		if r := p.match(c, depScope); r != nil {
			return Verdict{Action: r.Action, Rule: r.Match}
		}
	}
	category, known := lookup(cat, n.License)
	if !known {
		return Verdict{Action: p.unknown(), Rule: "unknown"}
	}
	if r := p.match(categoryMatch+category, depScope); r != nil {
		return Verdict{Action: r.Action, Rule: r.Match}
	}
	return Verdict{Action: p.defaultAction(), Rule: "default"}
}

func lookup(cat Catalog, id string) (string, bool) {
	key := strings.ToLower(id)
	if c, ok := cat[key]; ok {
		return c, true
	}
	if base, ok := strings.CutSuffix(key, "+"); ok {
		c, ok := cat[base]
		return c, ok
	}
	return "", false
}

// match returns the first rule for match (case-insensitive) that applies
// to depScope.
func (p *Policy) match(m, depScope string) *Rule {
	for i := range p.Rules {
		r := &p.Rules[i]
		if !strings.EqualFold(normalizeSpaces(r.Match), normalizeSpaces(m)) {
			continue
		}
		if len(r.Scopes) > 0 && !contains(r.Scopes, depScope) {
			continue
		}
		return r
	}
	return nil
}

func normalizeSpaces(s string) string { return strings.Join(strings.Fields(s), " ") }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Opens reports whether a verdict opens a finding under the policy.
func (p *Policy) Opens(a Action) bool {
	return a == ActionDeny || (a == ActionReview && p.ReviewFindings)
}
