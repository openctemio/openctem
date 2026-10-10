package vex

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Range is a version range: comparators that must all hold, written
// ">=1.2.0,<1.4.3". Versions compare with the inventory matcher's rules
// (numeric segments, pre-release tags before the release); a version that
// does not parse is never in a range.
type Range struct {
	terms []rangeTerm
}

type rangeTerm struct {
	op string
	v  vulnmatch.Version
}

var rangeOps = []string{">=", "<=", "!=", ">", "<", "="}

// ParseRange parses a range. It refuses empty terms, unknown operators,
// versions that do not parse and more than MaxRangeTerms terms.
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxRangeLen {
		return Range{}, invalid("version_range is empty or too long")
	}
	parts := strings.Split(s, ",")
	if len(parts) > MaxRangeTerms {
		return Range{}, invalid(fmt.Sprintf("version_range has more than %d terms", MaxRangeTerms))
	}
	r := Range{terms: make([]rangeTerm, 0, len(parts))}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		op := ""
		for _, o := range rangeOps {
			if strings.HasPrefix(p, o) {
				op = o
				break
			}
		}
		if op == "" {
			return Range{}, invalid("each version_range term starts with >=, <=, >, <, = or !=")
		}
		v, ok := vulnmatch.ParseVersion(strings.TrimSpace(p[len(op):]))
		if !ok {
			return Range{}, invalid("version_range names a version that cannot be compared")
		}
		r.terms = append(r.terms, rangeTerm{op: op, v: v})
	}
	return r, nil
}

// String is the canonical form ("">=1.2.0,<1.4.3").
func (r Range) String() string {
	parts := make([]string, len(r.terms))
	for i, t := range r.terms {
		parts[i] = t.op + t.v.String()
	}
	return strings.Join(parts, ",")
}

// Contains reports whether version satisfies every term.
func (r Range) Contains(version string) bool {
	v, ok := vulnmatch.ParseVersion(version)
	if !ok || len(r.terms) == 0 {
		return false
	}
	for _, t := range r.terms {
		c := v.Compare(t.v)
		var hold bool
		switch t.op {
		case ">=":
			hold = c >= 0
		case "<=":
			hold = c <= 0
		case ">":
			hold = c > 0
		case "<":
			hold = c < 0
		case "=":
			hold = c == 0
		case "!=":
			hold = c != 0
		}
		if !hold {
			return false
		}
	}
	return true
}
