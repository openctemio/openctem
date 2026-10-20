package querylang

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Executor runs plans on one backend. The Postgres executor
// (internal/infra/postgres) renders SQL with pgsql; another backend would
// implement the same two calls over the same Plan, inheriting its
// security context (Plan.Actor, Plan.EffectiveFilter).
type Executor interface {
	// Explain estimates the plan's cost without running it.
	Explain(ctx context.Context, p *Plan) (Estimate, error)
	// Run executes the plan and returns at most p.Limit rows.
	Run(ctx context.Context, p *Plan) (*Result, error)
}

// Matches is what a match returns: the findings a filter-only query
// selects, as ids.
type Matches struct {
	// Total is the number of matches.
	Total int
	// IDs are the first matches, oldest first, at most the limit.
	IDs []shared.ID
	// Truncated is set when more matches existed than the limit.
	Truncated bool
}

// ErrTimeout is returned by an executor when a query ran out of time.
var ErrTimeout = errors.New("querylang: the query took too long")

// Estimate is a backend's cost estimate.
type Estimate struct {
	// Rows is the estimated number of entity rows the filter reads.
	Rows float64 `json:"rows"`
	// Cost is the backend's own cost unit (Postgres planner cost).
	Cost float64 `json:"cost"`
}

// Result is a query result.
type Result struct {
	Columns []Column `json:"columns"`
	Rows    [][]any  `json:"rows"`
	// Truncated is set when more rows existed than the limit.
	Truncated bool `json:"truncated"`
}

// Describe renders the plan in plain words, for the Explain panel, e.g.
// "Count of findings where severity is critical, grouped by asset.type".
func Describe(p *Plan) string {
	var b strings.Builder
	b.WriteString(measuresPhrase(p))
	b.WriteString(" of " + p.entity.Noun)
	if p.query.Where != nil {
		b.WriteString(" where ")
		b.WriteString(describeExpr(p.query.Where, 0))
	}
	var groups []string
	if p.Bucket != nil {
		groups = append(groups, "per "+string(p.Bucket.Interval)+" of "+p.Bucket.Path)
	}
	if len(p.Dims) > 0 {
		names := make([]string, 0, len(p.Dims))
		for _, d := range p.Dims {
			names = append(names, d.Path)
		}
		groups = append(groups, "grouped by "+strings.Join(names, " and "))
	}
	if len(groups) > 0 {
		b.WriteString(", " + strings.Join(groups, ", "))
	}
	if len(p.Order) > 0 && (len(p.Dims) > 0 || p.Bucket != nil) {
		o := p.Order[0]
		dir := "ascending"
		if o.Desc {
			dir = "descending"
		}
		b.WriteString(", ordered by " + p.Columns[o.Column].Name + " " + dir)
	}
	if p.Limit < MaxGroups {
		b.WriteString(", first " + strconv.Itoa(p.Limit))
	}
	return b.String()
}

func measuresPhrase(p *Plan) string {
	parts := make([]string, 0, len(p.Aggs))
	for _, a := range p.Aggs {
		switch a.Func {
		case AggCount:
			parts = append(parts, "count")
		case AggDistinct:
			parts = append(parts, "number of distinct "+a.Path)
		case AggAvg:
			parts = append(parts, "average "+a.Path)
		case AggSum:
			parts = append(parts, "sum of "+a.Path)
		case AggMin:
			parts = append(parts, "lowest "+a.Path)
		case AggMax:
			parts = append(parts, "highest "+a.Path)
		case AggMedian:
			parts = append(parts, "median "+a.Path)
		case AggP90:
			parts = append(parts, "90th percentile of "+a.Path)
		}
	}
	s := strings.Join(parts, ", ")
	if s == "" {
		return "Count"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func describeExpr(e Expr, parent int) string {
	var s string
	switch x := e.(type) {
	case *Logic:
		word := " and "
		if x.Kind == Or {
			word = " or "
		}
		parts := make([]string, 0, len(x.Terms))
		for _, t := range x.Terms {
			parts = append(parts, describeExpr(t, precOf(e)))
		}
		s = strings.Join(parts, word)
	case *Not:
		s = "not (" + describeExpr(x.X, 0) + ")"
	case *Compare:
		words := opWords[x.Op]
		if w, ok := timeOpWords[x.Op]; ok && x.Value.Kind == ValRelative {
			words = w
		}
		s = x.Path.Name + " " + words + " " + describeValue(x.Value)
	case *In:
		vals := make([]string, 0, len(x.Values))
		for _, v := range x.Values {
			vals = append(vals, describeValue(v))
		}
		word := "is one of"
		if x.Negate {
			word = "is none of"
		}
		s = x.Path.Name + " " + word + " " + strings.Join(vals, ", ")
	case *Between:
		s = x.Path.Name + " is between " + describeValue(x.Lo) + " and " + describeValue(x.Hi)
	case *IsEmpty:
		if x.Negate {
			s = x.Path.Name + " is set"
		} else {
			s = x.Path.Name + " is not set"
		}
	case *Text:
		s = "the text contains " + Quote(x.Value.Text)
	}
	if precOf(e) <= parent {
		return "(" + s + ")"
	}
	return s
}

var opWords = map[CompareOp]string{
	OpEq: "is", OpNe: "is not", OpGt: "is greater than", OpGte: "is at least", OpLt: "is less than",
	OpLte: "is at most", OpContains: "contains",
}

var timeOpWords = map[CompareOp]string{
	OpGt: "is after", OpGte: "is on or after", OpLt: "is before", OpLte: "is on or before",
}

var unitWords = map[string]string{"h": "hours", "d": "days", "w": "weeks", "mo": "months", "y": "years"}

func describeValue(v Value) string {
	switch v.Kind {
	case ValRelative:
		i := 1
		for i < len(v.Text) && isDigit(v.Text[i]) {
			i++
		}
		return v.Text[1:i] + " " + unitWords[v.Text[i:]] + " ago"
	case ValString:
		return Quote(v.Text)
	case ValIdent:
		if strings.EqualFold(v.Text, "me") {
			return "me"
		}
	}
	return v.Text
}
