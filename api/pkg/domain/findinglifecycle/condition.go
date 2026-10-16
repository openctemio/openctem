package findinglifecycle

import (
	"fmt"
	"slices"
	"strings"
)

// Conditions decide whether a move's guards apply (TransitionSpec.When) and
// which context scheme a finding belongs to. The field catalog is closed and
// typed, and the operators compare values only: no regular expressions, no
// expressions, no functions.

// Condition is one comparison as written in a spec.
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// Condition fields.
const (
	CondSeverity      = "severity"
	CondPriorityClass = "priority_class"
	CondIsKEV         = "is_kev"
	CondSource        = "source"
	CondFindingType   = "finding_type"
	CondToolName      = "tool_name"
)

// Operators.
const (
	OpEq     = "eq"
	OpNeq    = "neq"
	OpIn     = "in"
	OpNotIn  = "not_in"
	OpGte    = "gte"
	OpLte    = "lte"
	OpExists = "exists"
)

type fieldKind int

const (
	kindOrdered fieldKind = iota // severity, priority_class
	kindString                   // source, finding_type, tool_name
	kindBool                     // is_kev
)

type fieldDef struct {
	kind fieldKind
	// values, when set, is the closed set of values and, for an ordered
	// field, their order from lowest to highest.
	values []string
}

var conditionFields = map[string]fieldDef{ //nolint:gochecknoglobals // static catalog
	CondSeverity:      {kind: kindOrdered, values: []string{"info", "low", "medium", "high", "critical"}},
	CondPriorityClass: {kind: kindOrdered, values: []string{"P3", "P2", "P1", "P0"}},
	CondIsKEV:         {kind: kindBool},
	CondSource:        {kind: kindString},
	CondFindingType:   {kind: kindString},
	CondToolName:      {kind: kindString},
}

// ConditionFields lists the catalog's fields.
func ConditionFields() []string {
	out := make([]string, 0, len(conditionFields))
	for f := range conditionFields {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// ConditionFacts are the finding values conditions read.
type ConditionFacts struct {
	Severity      string
	PriorityClass string
	IsKEV         bool
	Source        string
	FindingType   string
	ToolName      string
}

func (f ConditionFacts) value(field string) string {
	switch field {
	case CondSeverity:
		return f.Severity
	case CondPriorityClass:
		return f.PriorityClass
	case CondSource:
		return f.Source
	case CondFindingType:
		return f.FindingType
	case CondToolName:
		return f.ToolName
	}
	return ""
}

// compiledCondition is a checked condition.
type compiledCondition struct {
	field  string
	op     string
	values []string
	flag   bool
	rank   int
}

const maxConditionValueLen = 100

// compileCondition checks c against the catalog.
func compileCondition(c Condition) (compiledCondition, error) {
	def, ok := conditionFields[c.Field]
	if !ok {
		return compiledCondition{}, fmt.Errorf("unknown field %q", c.Field)
	}
	cc := compiledCondition{field: c.Field, op: c.Op}
	switch c.Op {
	case OpExists:
		if def.kind == kindBool {
			return cc, fmt.Errorf("%s does not support exists", c.Field)
		}
		b, ok := c.Value.(bool)
		if !ok {
			return cc, fmt.Errorf("exists takes true or false")
		}
		cc.flag = b
		return cc, nil
	case OpEq, OpNeq:
		if def.kind == kindBool {
			b, ok := c.Value.(bool)
			if !ok {
				return cc, fmt.Errorf("%s takes true or false", c.Field)
			}
			cc.flag = b
			return cc, nil
		}
		s, err := conditionString(def, c.Value)
		if err != nil {
			return cc, fmt.Errorf("%s: %w", c.Field, err)
		}
		cc.values = []string{s}
		return cc, nil
	case OpIn, OpNotIn:
		if def.kind == kindBool {
			return cc, fmt.Errorf("%s does not support %s", c.Field, c.Op)
		}
		raw, ok := c.Value.([]any)
		if !ok || len(raw) == 0 {
			return cc, fmt.Errorf("%s takes a non-empty list", c.Op)
		}
		if len(raw) > MaxListValues {
			return cc, fmt.Errorf("at most %d values", MaxListValues)
		}
		for _, v := range raw {
			s, err := conditionString(def, v)
			if err != nil {
				return cc, fmt.Errorf("%s: %w", c.Field, err)
			}
			if !slices.Contains(cc.values, s) {
				cc.values = append(cc.values, s)
			}
		}
		return cc, nil
	case OpGte, OpLte:
		if def.kind != kindOrdered {
			return cc, fmt.Errorf("%s is not ordered", c.Field)
		}
		s, err := conditionString(def, c.Value)
		if err != nil {
			return cc, fmt.Errorf("%s: %w", c.Field, err)
		}
		cc.rank = slices.Index(def.values, s)
		return cc, nil
	}
	return cc, fmt.Errorf("unknown operator %q", c.Op)
}

func conditionString(def fieldDef, v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("takes a text value")
	}
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxConditionValueLen {
		return "", fmt.Errorf("a value is 1-%d characters", maxConditionValueLen)
	}
	if def.values != nil && !slices.Contains(def.values, s) {
		return "", fmt.Errorf("%q is not one of %s", s, strings.Join(def.values, ", "))
	}
	return s, nil
}

// match reports whether the facts satisfy the condition.
func (c compiledCondition) match(f ConditionFacts) bool {
	if c.field == CondIsKEV {
		if c.op == OpNeq {
			return f.IsKEV != c.flag
		}
		return f.IsKEV == c.flag
	}
	v := f.value(c.field)
	switch c.op {
	case OpExists:
		return (v != "") == c.flag
	case OpEq:
		return v == c.values[0]
	case OpNeq:
		return v != c.values[0]
	case OpIn:
		return slices.Contains(c.values, v)
	case OpNotIn:
		return !slices.Contains(c.values, v)
	case OpGte, OpLte:
		r := slices.Index(conditionFields[c.field].values, v)
		if r < 0 {
			return false // no value is neither above nor below anything
		}
		if c.op == OpGte {
			return r >= c.rank
		}
		return r <= c.rank
	}
	return false
}

// matchAll reports whether every condition matches (an empty list matches).
func matchAll(cs []compiledCondition, f ConditionFacts) bool {
	for _, c := range cs {
		if !c.match(f) {
			return false
		}
	}
	return true
}
