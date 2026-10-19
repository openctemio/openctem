package pgsql

import (
	"errors"
	"strconv"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// MatchOptions narrows a match: the findings a filter-only query selects,
// as ids (a remediation task created from a query).
type MatchOptions struct {
	// Limit is the most ids returned; the statement fetches one more to
	// detect truncation.
	Limit int
	// ExcludeStatuses leaves out findings in these statuses (closed ones).
	ExcludeStatuses []string
	// ExcludeSources leaves out findings from these sources (pentest).
	ExcludeSources []string
	// ExcludeClaimed leaves out findings that are already the primary
	// member of a remediation task (the one-task-per-finding rule).
	ExcludeClaimed bool
}

// MatchStatement is a rendered match: a count over every match and the
// first Limit+1 ids, oldest first, with the same arguments.
type MatchStatement struct {
	CountSQL string
	IDsSQL   string
	Args     []any
	Limit    int
}

// ErrMatchNeedsFilter refuses a plan that is not a filter-only findings
// query: a match returns findings, not aggregates.
var ErrMatchNeedsFilter = errors.New("pgsql: a match needs a findings query without pipeline stages")

// claimedSQL: an active primary membership, the rows the unique index
// ux_remediation_task_members_primary covers.
const claimedSQL = ` AND NOT EXISTS (SELECT 1 FROM remediation_task_members m
	WHERE m.tenant_id = findings.tenant_id AND m.finding_id = findings.id AND m.left_at IS NULL AND m.role = 'primary')`

// RenderMatch builds the match statements for a filter-only findings plan.
// The WHERE clause is the plan's effective filter compiled as the plan's
// actor (tenant, data scope, member visibility, mandatory filters), like
// Render; the options only narrow it further.
func RenderMatch(p *querylang.Plan, o MatchOptions) (*MatchStatement, error) {
	if p == nil {
		return nil, errors.New("pgsql: nil plan")
	}
	if p.Entity().Name != querylang.Findings.Name || len(p.Query().Pipeline) > 0 {
		return nil, ErrMatchNeedsFilter
	}
	if o.Limit <= 0 {
		return nil, errors.New("pgsql: match without a limit")
	}
	actor := p.Actor()
	if actor.TenantID().IsZero() {
		return nil, errors.New("pgsql: plan without a tenant")
	}
	where, err := filterspec.CompileFrom(p.EffectiveFilter(), p.Entity().Registry, actor, 1)
	if err != nil {
		return nil, err
	}
	args := append([]any{}, where.Args...)
	cond := where.SQL
	if len(o.ExcludeStatuses) > 0 {
		args = append(args, pq.StringArray(o.ExcludeStatuses))
		cond += " AND findings.status <> ALL($" + strconv.Itoa(len(args)) + "::text[])"
	}
	if len(o.ExcludeSources) > 0 {
		args = append(args, pq.StringArray(o.ExcludeSources))
		cond += " AND findings.source <> ALL($" + strconv.Itoa(len(args)) + "::text[])"
	}
	if o.ExcludeClaimed {
		cond += claimedSQL
	}
	return &MatchStatement{
		CountSQL: "SELECT count(*) FROM findings WHERE " + cond,
		IDsSQL: "SELECT findings.id FROM findings WHERE " + cond +
			" ORDER BY findings.created_at, findings.id LIMIT " + strconv.Itoa(o.Limit+1),
		Args:  args,
		Limit: o.Limit,
	}, nil
}
