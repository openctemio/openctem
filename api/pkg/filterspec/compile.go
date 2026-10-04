package filterspec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Actor is who a filter runs as. It cannot be built without a tenant, and
// the zero value is rejected by Compile.
type Actor struct {
	tenantID shared.ID
	userID   shared.ID
	isAdmin  bool
	scope    *shared.DataScope
	system   bool
	reason   string
	has      func(permission string) bool
}

// UserActorInput describes a request's caller.
type UserActorInput struct {
	TenantID shared.ID
	// UserID is the acting user; zero for a user-less API key.
	UserID shared.ID
	// IsAdmin is the request's owner/admin decision.
	IsAdmin bool
	// Scope is datascope.Enforcer.Resolve for this tenant: nil only for an
	// unrestricted caller (administrator, or a member of a fail-open tenant
	// with no scope row).
	Scope *shared.DataScope
	// Has reports the caller's permissions, for fields with a Permission;
	// nil denies every such field.
	Has func(permission string) bool
}

// UserActor is a request's caller.
func UserActor(in UserActorInput) (Actor, error) {
	if in.TenantID.IsZero() {
		return Actor{}, errors.New("filterspec: actor without a tenant")
	}
	if in.Scope != nil && in.Scope.TenantID != in.TenantID {
		return Actor{}, errors.New("filterspec: data scope belongs to another tenant")
	}
	if in.Scope != nil && in.Scope.UserID != in.UserID {
		return Actor{}, errors.New("filterspec: data scope belongs to another user")
	}
	return Actor{tenantID: in.TenantID, userID: in.UserID, isAdmin: in.IsAdmin, scope: in.Scope, has: in.Has}, nil
}

// SystemActor is background work whose output only administrators see. It
// keeps the tenant predicate and skips the data scope and the registry's
// member visibility rule. Call sites are allowlisted
// (systemactor_allowlist_test.go); reason is logged by callers.
func SystemActor(tenantID shared.ID, reason string) Actor {
	return Actor{tenantID: tenantID, system: true, reason: reason}
}

// TenantID returns the actor's tenant.
func (a Actor) TenantID() shared.ID { return a.tenantID }

// Restricted reports whether a data-scope predicate applies.
func (a Actor) Restricted() bool { return a.scope != nil && !a.system }

// member reports whether the registry's member visibility rule applies:
// every request caller that is not an administrator.
func (a Actor) member() bool { return !a.system && !a.isAdmin }

func (a Actor) may(permission string) bool {
	if permission == "" || a.system {
		return true
	}
	return a.has != nil && a.has(permission)
}

// Where is a compiled filter.
type Where struct {
	// SQL is a boolean expression starting with the tenant predicate.
	SQL string
	// Args are the bound values, numbered from the start argument.
	Args []any
	// OrderBy is "expr [DESC], ..., id" (without the ORDER BY keyword).
	OrderBy string
	// First is the first placeholder number; NextArg the next free one.
	First   int
	NextArg int
}

// Compile turns a spec into SQL for reg, as actor, with placeholders from $1.
func Compile(spec *Spec, reg *Registry, actor Actor) (*Where, error) {
	return CompileFrom(spec, reg, actor, 1)
}

// CompileFrom is Compile with placeholders starting at $first, for queries
// that bind other values before the filter.
func CompileFrom(spec *Spec, reg *Registry, actor Actor, first int) (*Where, error) {
	if reg == nil || spec == nil {
		return nil, errors.New("filterspec: nil registry or spec")
	}
	if actor.tenantID.IsZero() {
		return nil, errors.New("filterspec: actor without a tenant")
	}
	if first < 1 {
		first = 1
	}
	c := &compiler{reg: reg, actor: actor, next: first}

	c.tenantPH = c.bind(actor.tenantID.String())
	parts := []string{reg.TenantSQL + " = " + c.tenantPH}
	// An Unscoped registry (tenant configuration) has no asset to scope by;
	// its registry records why.
	if actor.Restricted() && reg.ScopeAssetSQL != "" {
		cond, args := ScopeSQL(reg.ScopeAssetSQL, actor.scope, c.next)
		parts = append(parts, cond)
		c.args = append(c.args, args...)
		c.next += len(args)
	}
	if reg.MemberVisibility != "" && actor.member() {
		parts = append(parts, "("+c.render(reg.MemberVisibility, "")+")")
	}
	if spec.Root != nil {
		if s := c.node(spec.Root); s != "" {
			parts = append(parts, s)
		}
	}
	if spec.Q != "" && reg.Search != nil {
		v := spec.Q
		if reg.Search.Pattern {
			v = "%" + EscapeLike(v) + "%"
		}
		parts = append(parts, "("+c.render(reg.Search.Template, c.bind(v))+")")
	}
	order := c.orderBy(spec.Sort)
	if err := c.e.err(); err != nil {
		return nil, err
	}
	return &Where{SQL: strings.Join(parts, " AND "), Args: c.args, OrderBy: order, First: first, NextArg: c.next}, nil
}

// ScopeSQL is the data-scope predicate "assetExpr is in the user's scope",
// with placeholders $first and $first+1. It must stay identical to
// postgres.dataScopeCondAt (a test there pins them together).
func ScopeSQL(assetExpr string, scope *shared.DataScope, first int) (string, []any) {
	return fmt.Sprintf(
			"%s IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $%d AND uaa.tenant_id = $%d)",
			assetExpr, first, first+1),
		[]any{scope.UserID.String(), scope.TenantID.String()}
}

// EscapeLike escapes LIKE metacharacters for a pattern used with ESCAPE '\'.
func EscapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

type compiler struct {
	reg      *Registry
	actor    Actor
	args     []any
	next     int
	e        errs
	tenantPH string
	userPH   string
}

// render substitutes the template tokens: ArgToken with argPH, TenantToken
// with the tenant placeholder, UserToken with the acting user (bound once
// per compile; the zero UUID for a caller without a user, which matches no
// row, so a user-relative rule fails closed).
func (c *compiler) render(tpl, argPH string) string {
	if strings.Contains(tpl, UserToken) && c.userPH == "" {
		c.userPH = c.bind(c.actor.userID.String()) + "::uuid"
	}
	return strings.NewReplacer(ArgToken, argPH, TenantToken, c.tenantPH, UserToken, c.userPH).Replace(tpl)
}

func (c *compiler) bind(v any) string {
	c.args = append(c.args, v)
	p := "$" + strconv.Itoa(c.next)
	c.next++
	return p
}

func (c *compiler) node(n *Node) string {
	switch {
	case n.Leaf != nil:
		return c.leaf(n.Leaf)
	case n.Not != nil:
		inner := c.node(n.Not)
		if inner == "" {
			return ""
		}
		// NOT over a three-valued predicate: a NULL comparison must count as
		// "not matched", so NOT(NULL) is treated as true.
		return "(NOT COALESCE(" + inner + ", FALSE))"
	case n.Any != nil:
		return c.group(n.Any, " OR ", "FALSE")
	default:
		return c.group(n.All, " AND ", "TRUE")
	}
}

func (c *compiler) group(kids []*Node, sep, empty string) string {
	parts := make([]string, 0, len(kids))
	for _, k := range kids {
		if s := c.node(k); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return empty
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func (c *compiler) leaf(l *Leaf) string {
	f, ok := c.reg.fields[l.Field]
	if !ok || !c.actor.may(f.Permission) || !f.allows(l.Op) {
		// Same answer for a missing field and a forbidden one: no oracle.
		c.fail(l, "unknown field")
		return ""
	}
	if f.BoolTemplate != "" && l.Op == OpEq {
		if l.Values[0] == true {
			return "(" + c.render(f.BoolTemplate, "") + ")"
		}
		return "(NOT COALESCE((" + c.render(f.BoolTemplate, "") + "), FALSE))"
	}
	if tpl, ok := f.Templates[l.Op]; ok {
		if strings.Contains(tpl, UserToken) && (c.actor.system || c.actor.userID.IsZero()) {
			// "related to me" has no meaning without a user.
			c.fail(l, "unknown field")
			return ""
		}
		return c.template(f, l, tpl)
	}
	col := f.SQL
	switch l.Op {
	case OpEq:
		return "(" + col + " = " + c.bindValue(f, l.Values[0]) + ")"
	case OpNe:
		s := col + " <> " + c.bindValue(f, l.Values[0])
		if f.Nullable {
			return "(" + s + " OR " + col + " IS NULL)"
		}
		return "(" + s + ")"
	case OpIn:
		if len(l.Values) == 1 {
			return "(" + col + " = " + c.bindValue(f, l.Values[0]) + ")"
		}
		return "(" + col + " = ANY(" + c.bindArray(f, l.Values) + "))"
	case OpNotIn:
		s := col + " <> ALL(" + c.bindArray(f, l.Values) + ")"
		if f.Nullable {
			return "(" + s + " OR " + col + " IS NULL)"
		}
		return "(" + s + ")"
	case OpGte:
		return "(" + col + " >= " + c.bindValue(f, l.Values[0]) + ")"
	case OpGt:
		return "(" + col + " > " + c.bindValue(f, l.Values[0]) + ")"
	case OpLte:
		return "(" + col + " <= " + c.bindValue(f, l.Values[0]) + ")"
	case OpLt:
		return "(" + col + " < " + c.bindValue(f, l.Values[0]) + ")"
	case OpIsNull:
		if l.Values[0] == true {
			return "(" + col + " IS NULL)"
		}
		return "(" + col + " IS NOT NULL)"
	case OpContains:
		s, _ := l.Values[0].(string)
		return "(" + col + " ILIKE " + c.bind("%"+EscapeLike(s)+"%") + ` ESCAPE '\')`
	}
	c.fail(l, "unsupported operator")
	return ""
}

// template renders a registry template. Multi-value operators bind one
// array; others bind the single value. is_null templates bind nothing.
func (c *compiler) template(f *Field, l *Leaf, tpl string) string {
	if l.Op == OpIsNull {
		if l.Values[0] == true {
			return "(" + c.render(tpl, "") + ")"
		}
		return "(NOT (" + c.render(tpl, "") + "))"
	}
	if !strings.Contains(tpl, ArgToken) {
		// A constant-value field ("related_to=me"): nothing to bind.
		return "(" + c.render(tpl, "") + ")"
	}
	var ph string
	switch l.Op {
	case OpIn, OpNotIn:
		ph = c.bindArray(f, l.Values)
	case OpContains:
		s, _ := l.Values[0].(string)
		ph = c.bind("%" + EscapeLike(s) + "%")
	default:
		ph = c.bindValue(f, l.Values[0])
	}
	return "(" + c.render(tpl, ph) + ")"
}

func (c *compiler) bindValue(f *Field, v any) string {
	p := c.bind(v)
	switch f.Type {
	case TypeID:
		return p + "::uuid"
	case TypeTime:
		return p + "::timestamptz"
	case TypeInt:
		return p + "::bigint"
	case TypeNumber:
		// No cast: the parameter takes the column's type (numeric columns
		// keep their index; a float8 cast would cast the column instead).
		return p
	case TypeBool:
		return p + "::boolean"
	}
	return p
}

func (c *compiler) bindArray(f *Field, vals []any) string {
	switch f.Type {
	case TypeInt:
		a := make([]int64, len(vals))
		for i, v := range vals {
			a[i], _ = v.(int64)
		}
		return c.bind(pq.Array(a)) + "::bigint[]"
	case TypeNumber:
		a := make([]float64, len(vals))
		for i, v := range vals {
			a[i], _ = v.(float64)
		}
		return c.bind(pq.Array(a)) // typed by the column, as above
	case TypeBool:
		a := make([]bool, len(vals))
		for i, v := range vals {
			a[i], _ = v.(bool)
		}
		return c.bind(pq.Array(a)) + "::boolean[]"
	case TypeTime:
		a := make([]string, len(vals))
		for i, v := range vals {
			t, _ := v.(time.Time)
			a[i] = t.Format(time.RFC3339Nano)
		}
		return c.bind(pq.Array(a)) + "::timestamptz[]"
	}
	a := make([]string, len(vals))
	for i, v := range vals {
		a[i], _ = v.(string)
	}
	if f.Type == TypeID {
		return c.bind(pq.Array(a)) + "::uuid[]"
	}
	return c.bind(pq.Array(a)) + "::text[]"
}

func (c *compiler) orderBy(keys []SortKey) string {
	if len(keys) == 0 {
		keys = c.reg.DefaultSort
	}
	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		f, ok := c.reg.fields[k.Field]
		if !ok || !f.Sortable || !c.actor.may(f.Permission) {
			c.e.param("sort", "not a sortable field", safeName(k.Field), false)
			continue
		}
		expr := f.SortSQL
		if expr == "" {
			expr = f.SQL
		}
		// Postgres defaults (ASC NULLS LAST, DESC NULLS FIRST) so the order
		// matches the sort indexes of non-null columns; a nullable field
		// sorted descending keeps its unset rows last ("highest CVSS first"
		// must not start with the unscored).
		switch {
		case k.Desc && f.Nullable:
			expr += " DESC NULLS LAST"
		case k.Desc:
			expr += " DESC"
		default:
			expr += " ASC"
		}
		parts = append(parts, expr)
	}
	parts = append(parts, c.reg.IDSQL)
	return strings.Join(parts, ", ")
}

func (c *compiler) fail(l *Leaf, reason string) {
	if l.srcPath {
		c.e.path(l.src, reason, "", true)
		return
	}
	src := l.src
	if src == "" {
		src = l.Field
	}
	c.e.param(src, reason, "", true)
}
