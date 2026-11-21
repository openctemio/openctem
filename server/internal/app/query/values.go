package query

// Value completion for search boxes (docs/architecture/query-language.md,
// "Short form"): the most frequent values of one field with their counts,
// under the caller's own filter minus that field. It is an ordinary query
// ("findings where <filter> | count by field | top N by count") built and
// run through the plan layer, so the tenant, the data scope, the pentest
// member rule and the mandatory exclusions apply exactly as for the list.
//
// Answers are not kept between requests: every call resolves the caller's
// data scope and runs the query, so a removed group, grant, campaign
// membership or role changes the next answer (the 0-second revocation of
// docs/architecture/permission-realtime-sync.md). The 1 s budget and the
// per-user, per-tenant and per-process slots bound the cost instead.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/querylang"
)

// Value completion limits.
const (
	// ValuesBudget is the time a values call may take; past it the answer
	// has no counts rather than late or wrong ones.
	ValuesBudget = time.Second
	// MaxValues is the most values returned.
	MaxValues    = 20
	maxPrefixLen = 100
)

// ValuesInput asks for the values of one field.
type ValuesInput struct {
	Entity string
	// Field is a path or short name the caller may use ("tool", "severity").
	Field string
	// Prefix narrows the values (case-insensitive).
	Prefix string
	// Filter is the search box text the counts are computed under (short
	// or long form); the field's own top-level conditions are left out.
	Filter string
}

// ValueCount is one value and how many rows have it.
type ValueCount struct {
	Value any `json:"value"`
	// Count is nil when Counted is false.
	Count *int64 `json:"count,omitempty"`
}

// ValuesResult is the answer of Values.
type ValuesResult struct {
	Entity string       `json:"entity"`
	Field  string       `json:"field"`
	Values []ValueCount `json:"values"`
	// Counted is false when the counts did not finish within the budget:
	// enum and boolean values are then listed without counts.
	Counted bool `json:"counted"`
}

// ErrUnknownField is a values request for a field the caller may not use
// or that has no values (one answer for both).
var ErrUnknownField = fmt.Errorf("%w: unknown field", shared.ErrValidation)

// Values returns the most frequent values of a field under the caller's
// filter, counted in the caller's scope.
func (s *Service) Values(ctx context.Context, c Caller, in ValuesInput) (*ValuesResult, error) {
	ent, ok := querylang.Lookup(in.Entity)
	if !ok {
		return nil, fmt.Errorf("%w: unknown entity", shared.ErrNotFound)
	}
	has := func(p string) bool { return c.IsAdmin || (c.Has != nil && c.Has(p)) }
	if !has(ent.Permission) {
		return nil, fmt.Errorf("%w: entity", shared.ErrForbidden)
	}
	path := ent.Canonical(strings.ToLower(strings.TrimSpace(in.Field)))
	field, ok := valuesField(ent, path, has)
	if !ok {
		return nil, ErrUnknownField
	}
	prefix := strings.ToLower(strings.TrimSpace(in.Prefix))
	if len(prefix) > maxPrefixLen {
		return nil, fmt.Errorf("%w: prefix too long", shared.ErrValidation)
	}
	q, _, err := querylang.ParseFilter(ent, in.Filter)
	if err != nil {
		return nil, err
	}
	q.Where = withoutPath(ent, q.Where, path)
	n := querylang.MaxGroups
	if prefix == "" {
		n = MaxValues
	}
	q.Pipeline = []querylang.Stage{
		{Kind: querylang.StageCount, By: []querylang.Path{{Name: path}}},
		{Kind: querylang.StageSort, Keys: []querylang.SortKey{{Name: querylang.Path{Name: "count"}, Desc: true}}},
		{Kind: querylang.StageLimit, N: n},
	}
	pr, err := s.principal(ctx, c)
	if err != nil {
		return nil, err
	}
	plan, err := querylang.Build(q, in.Filter, pr, querylang.BuildOptions{Now: s.now})
	if err != nil {
		return nil, err
	}
	release, err := s.limiter.acquire(c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	defer release()
	runCtx, cancel := context.WithTimeout(ctx, ValuesBudget)
	defer cancel()
	out, err := s.exec.Run(runCtx, plan)
	res := &ValuesResult{Entity: ent.Name, Field: path, Values: []ValueCount{}}
	switch {
	case errors.Is(err, querylang.ErrTimeout) || errors.Is(err, context.DeadlineExceeded):
		res.Values = uncounted(field, prefix)
		return res, nil
	case err != nil:
		return nil, err
	}
	res.Counted = true
	for _, row := range out.Rows {
		if len(row) < 2 || row[0] == nil {
			continue
		}
		if prefix != "" && !strings.HasPrefix(strings.ToLower(fmt.Sprint(row[0])), prefix) {
			continue
		}
		cnt, _ := row[1].(int64)
		res.Values = append(res.Values, ValueCount{Value: row[0], Count: &cnt})
		if len(res.Values) == MaxValues {
			break
		}
	}
	return res, nil
}

// valuesField resolves a path the caller may use that the entity can
// group by (its dimensions).
func valuesField(ent *querylang.Entity, path string, has func(string) bool) (*filterspec.Field, bool) {
	fieldName := ent.Dimension(path)
	if fieldName == "" {
		return nil, false
	}
	f, ok := ent.Registry.Field(fieldName)
	if !ok || (f.Permission != "" && !has(f.Permission)) {
		return nil, false
	}
	return f, true
}

// uncounted lists the values of an enum or boolean field without counts.
func uncounted(f *filterspec.Field, prefix string) []ValueCount {
	var vals []string
	switch f.Type {
	case filterspec.TypeEnum:
		vals = f.Enum
	case filterspec.TypeBool:
		vals = []string{"true", "false"}
	}
	out := []ValueCount{}
	for _, v := range vals {
		if strings.HasPrefix(strings.ToLower(v), prefix) && len(out) < MaxValues {
			out = append(out, ValueCount{Value: v})
		}
	}
	return out
}

// withoutPath drops the top-level conditions on path (the values of a
// field are counted with every other filter applied).
func withoutPath(ent *querylang.Entity, x querylang.Expr, path string) querylang.Expr {
	on := func(e querylang.Expr) bool {
		switch n := e.(type) {
		case *querylang.Compare:
			return ent.Canonical(n.Path.Name) == path
		case *querylang.In:
			return ent.Canonical(n.Path.Name) == path
		case *querylang.Between:
			return ent.Canonical(n.Path.Name) == path
		case *querylang.IsEmpty:
			return ent.Canonical(n.Path.Name) == path
		}
		return false
	}
	if x == nil || on(x) {
		return nil
	}
	l, ok := x.(*querylang.Logic)
	if !ok || l.Kind != querylang.And {
		return x
	}
	kept := make([]querylang.Expr, 0, len(l.Terms))
	for _, t := range l.Terms {
		if !on(t) {
			kept = append(kept, t)
		}
	}
	switch len(kept) {
	case 0:
		return nil
	case 1:
		return kept[0]
	}
	return &querylang.Logic{Kind: querylang.And, Terms: kept, Span: l.Span}
}
