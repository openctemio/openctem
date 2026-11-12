// Package pgsql renders a querylang.Plan as one parameterised PostgreSQL
// statement. Every SQL fragment is a constant from this file or from the
// entity's filterspec registry; query values are bound parameters only.
// The WHERE clause is always filterspec.CompileFrom over the plan's
// effective filter as the plan's actor, so the tenant predicate, the data
// scope, the member visibility rule and the mandatory filters are part of
// every statement.
//
// Design: docs/architecture/query-language.md.
package pgsql

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// tenantToken in a binding is the statement's own tenant parameter ($1,
// bound only when an expression uses it).
const tenantToken = "{tenant}"

// binding is the Postgres side of an entity: its table and the SQL of the
// paths whose registry SQL is not a plain column.
type binding struct {
	table string
	exprs map[string]string
}

func findingAsset(col string) string {
	return "(SELECT a." + col + " FROM assets a WHERE a.tenant_id = {tenant} AND a.id = findings.asset_id)"
}

var bindings = map[string]binding{
	"findings": {table: "findings", exprs: map[string]string{
		"asset.type":            findingAsset("asset_type"),
		"asset.criticality":     findingAsset("criticality"),
		"asset.environment":     findingAsset("environment"),
		"asset.exposure":        findingAsset("exposure"),
		"asset.internet_facing": "COALESCE(" + findingAsset("is_internet_accessible") + ", FALSE)",
		"asset.crown_jewel":     "COALESCE(" + findingAsset("is_crown_jewel") + ", FALSE)",
		"observation":           "findings.observation_state",
		"validation":            "findings.validation_outcome",
	}},
	"assets": {table: "assets", exprs: map[string]string{
		"internet_facing": "COALESCE(assets.is_internet_accessible, FALSE)",
		"crown_jewel":     "COALESCE(assets.is_crown_jewel, FALSE)",
	}},
}

var intervals = map[querylang.Interval]string{
	querylang.IntervalDay: "day", querylang.IntervalWeek: "week", querylang.IntervalMonth: "month",
}

// Statement is a rendered plan.
type Statement struct {
	SQL  string
	Args []any
	// Limit is the plan's row cap; SQL fetches one more row to detect
	// truncation.
	Limit int
	// Grouped is false for a single-row aggregate.
	Grouped bool
}

// Expr returns the SQL of an entity path (a dimension, measure or time),
// with tenantToken unreplaced. It errors for a path the entity does not
// bind, so a declaration that the executor cannot serve fails its test.
func Expr(ent *querylang.Entity, path, field string) (string, error) {
	b, ok := bindings[ent.Name]
	if !ok {
		return "", fmt.Errorf("pgsql: no binding for entity %q", ent.Name)
	}
	if e, ok := b.exprs[path]; ok {
		return e, nil
	}
	if strings.Contains(path, ".") {
		return "", fmt.Errorf("pgsql: relation path %q has no binding", path)
	}
	f, ok := ent.Registry.Field(field)
	if !ok || strings.ContainsAny(f.SQL, "{}") || strings.Contains(f.SQL, "SELECT") {
		return "", fmt.Errorf("pgsql: path %q is not a plain column", path)
	}
	return f.SQL, nil
}

// Render builds the statement for a plan.
func Render(p *querylang.Plan) (*Statement, error) {
	if p == nil {
		return nil, errors.New("pgsql: nil plan")
	}
	ent := p.Entity()
	b, ok := bindings[ent.Name]
	if !ok {
		return nil, fmt.Errorf("pgsql: no binding for entity %q", ent.Name)
	}
	actor := p.Actor()
	if actor.TenantID().IsZero() {
		return nil, errors.New("pgsql: plan without a tenant")
	}
	// Expressions first: a relation expression binds the tenant as $1 and
	// the compiled filter then starts at $2.
	sel := make([]string, 0, len(p.Columns))
	if bk := p.Bucket; bk != nil {
		e, err := Expr(ent, bk.Path, bk.Field)
		if err != nil {
			return nil, err
		}
		iv, ok := intervals[bk.Interval]
		if !ok {
			return nil, fmt.Errorf("pgsql: unknown interval %q", bk.Interval)
		}
		sel = append(sel, "date_trunc('"+iv+"', "+e+" AT TIME ZONE 'UTC')")
	}
	for _, d := range p.Dims {
		e, err := Expr(ent, d.Path, d.Field)
		if err != nil {
			return nil, err
		}
		f, _ := ent.Registry.Field(d.Field)
		if f.Type != filterspec.TypeBool {
			e = "(" + e + ")::text"
		}
		sel = append(sel, e)
	}
	groups := len(sel)
	for _, a := range p.Aggs {
		s, err := aggSQL(ent, a)
		if err != nil {
			return nil, err
		}
		sel = append(sel, s)
	}
	first, args := 1, []any{}
	for _, s := range sel {
		if strings.Contains(s, tenantToken) {
			first, args = 2, []any{actor.TenantID().String()}
			break
		}
	}
	where, err := filterspec.CompileFrom(p.EffectiveFilter(), ent.Registry, actor, first)
	if err != nil {
		return nil, err
	}
	args = append(args, where.Args...)
	sub := strings.NewReplacer(tenantToken, "$1::uuid")
	for i, s := range sel {
		sel[i] = sub.Replace(s) + " AS c" + strconv.Itoa(i)
	}

	var q strings.Builder
	q.WriteString("SELECT " + strings.Join(sel, ", ") + " FROM " + b.table + " WHERE " + where.SQL)
	st := &Statement{Args: args, Limit: p.Limit, Grouped: groups > 0}
	if groups > 0 {
		gb := make([]string, 0, groups)
		for i := 1; i <= groups; i++ {
			gb = append(gb, strconv.Itoa(i))
		}
		q.WriteString(" GROUP BY " + strings.Join(gb, ", "))
	}
	if len(p.Order) > 0 && groups > 0 {
		ob := make([]string, 0, len(p.Order))
		for _, o := range p.Order {
			dir := " ASC NULLS LAST"
			if o.Desc {
				dir = " DESC NULLS LAST"
			}
			ob = append(ob, "c"+strconv.Itoa(o.Column)+dir)
		}
		q.WriteString(" ORDER BY " + strings.Join(ob, ", "))
	}
	if groups > 0 {
		q.WriteString(" LIMIT " + strconv.Itoa(p.Limit+1))
	}
	st.SQL = q.String()
	return st, nil
}

func aggSQL(ent *querylang.Entity, a querylang.AggRef) (string, error) {
	if a.Func == querylang.AggCount {
		return "count(*)", nil
	}
	e, err := Expr(ent, a.Path, a.Field)
	if err != nil {
		return "", err
	}
	switch a.Func {
	case querylang.AggDistinct:
		return "count(DISTINCT " + e + ")", nil
	case querylang.AggSum:
		return "sum(" + e + ")::float8", nil
	case querylang.AggAvg:
		return "avg(" + e + ")::float8", nil
	case querylang.AggMin:
		return "min(" + e + ")::float8", nil
	case querylang.AggMax:
		return "max(" + e + ")::float8", nil
	case querylang.AggMedian:
		return "percentile_cont(0.5) WITHIN GROUP (ORDER BY " + e + ")", nil
	case querylang.AggP90:
		return "percentile_cont(0.9) WITHIN GROUP (ORDER BY " + e + ")", nil
	}
	return "", fmt.Errorf("pgsql: unknown aggregate %q", a.Func)
}
