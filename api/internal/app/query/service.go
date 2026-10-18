// Package query runs custom queries (docs/architecture/query-language.md)
// for a request's caller: it resolves the caller's principal (tenant, data
// scope, permissions) on the server, builds the plan with pkg/querylang,
// bounds concurrency per user and per tenant, and hands the plan to the
// executor. Nothing in the query text can change the principal.
package query

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// Concurrency caps for interactive runs and explains. MaxPerProcess
// bounds all tenants together, so custom queries can hold only part of the
// API's database connection pool (25 by default) and many tenants at their
// own cap cannot starve every other request.
const (
	MaxPerUser    = 2
	MaxPerTenant  = 4
	MaxPerProcess = 8
)

// ErrBusy is returned when the caller or the tenant already runs the
// maximum number of queries (429).
var ErrBusy = errors.New("too many queries running; try again in a moment")

// Caller is the request's caller.
type Caller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
	APIKey   bool
	// Has reports the caller's permissions.
	Has func(permission string) bool
}

// Service runs custom queries.
type Service struct {
	exec      querylang.Executor
	dataScope *datascope.Enforcer
	limiter   *limiter
	logger    *logger.Logger
	now       func() time.Time
}

// NewService returns a query service.
func NewService(exec querylang.Executor, dataScope *datascope.Enforcer, log *logger.Logger) *Service {
	return &Service{exec: exec, dataScope: dataScope, limiter: newLimiter(MaxPerUser, MaxPerTenant, MaxPerProcess), logger: log, now: time.Now}
}

// Explanation is what Explain returns.
type Explanation struct {
	// Query is the canonical text.
	Query       string             `json:"query"`
	Description string             `json:"description"`
	Entity      string             `json:"entity"`
	Columns     []querylang.Column `json:"columns"`
	Scope       Scope              `json:"scope"`
	Score       int                `json:"score"`
	MaxScore    int                `json:"max_score"`
	Limit       int                `json:"limit"`
	// Cost is the estimated cost class (low, medium, high); empty when the
	// backend could not estimate. Raw planner numbers are not returned:
	// they derive from table-wide statistics that span tenants.
	Cost     string         `json:"cost,omitempty"`
	Document map[string]any `json:"document"`
}

// Scope states which rows the query is computed over.
type Scope struct {
	// Kind is "data_scope" (the caller's scope) or "organization" (an
	// administrator: every row except hidden program assets).
	Kind string `json:"kind"`
	// Rules are the server-side rules applied, in plain words.
	Rules []string `json:"rules"`
}

// RunResult is what Run returns.
type RunResult struct {
	Query      string             `json:"query"`
	Columns    []querylang.Column `json:"columns"`
	Rows       [][]any            `json:"rows"`
	Truncated  bool               `json:"truncated"`
	ElapsedMS  int64              `json:"elapsed_ms"`
	Scope      Scope              `json:"scope"`
	Limit      int                `json:"limit"`
	Complexity int                `json:"score"`
}

// Schema returns what the caller may use on an entity.
func (s *Service) Schema(_ context.Context, c Caller, entity string) (querylang.Schema, error) {
	ent, ok := querylang.Lookup(entity)
	if !ok {
		return querylang.Schema{}, fmt.Errorf("%w: unknown entity", shared.ErrNotFound)
	}
	has := func(p string) bool { return c.IsAdmin || (c.Has != nil && c.Has(p)) }
	if !has(ent.Permission) {
		return querylang.Schema{}, fmt.Errorf("%w: entity", shared.ErrForbidden)
	}
	return ent.Schema(has), nil
}

// Explain checks the query and describes it, with the backend's estimate.
func (s *Service) Explain(ctx context.Context, c Caller, text string) (*Explanation, error) {
	plan, err := s.plan(ctx, c, text)
	if err != nil {
		return nil, err
	}
	release, err := s.limiter.acquire(c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	defer release()
	ex := &Explanation{
		Query: querylang.Format(plan.Query()), Description: querylang.Describe(plan), Entity: plan.Entity().Name,
		Columns: plan.Columns, Scope: scopeOf(plan), Score: plan.Score, MaxScore: querylang.MaxScore,
		Limit: plan.Limit, Document: plan.Document(),
	}
	if est, err := s.exec.Explain(ctx, plan); err == nil {
		ex.Cost = costClass(est)
	} else if s.logger != nil {
		s.logger.Warn("query explain estimate failed", "entity", plan.Entity().Name, "error", err)
	}
	return ex, nil
}

// Run executes the query interactively. Runs are not audited (nothing is
// stored); saved queries, and their changes, will be.
func (s *Service) Run(ctx context.Context, c Caller, text string) (*RunResult, error) {
	plan, err := s.plan(ctx, c, text)
	if err != nil {
		return nil, err
	}
	release, err := s.limiter.acquire(c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	defer release()
	start := s.now()
	res, err := s.exec.Run(ctx, plan)
	if err != nil {
		return nil, err
	}
	return &RunResult{
		Query: querylang.Format(plan.Query()), Columns: res.Columns, Rows: res.Rows, Truncated: res.Truncated,
		ElapsedMS: s.now().Sub(start).Milliseconds(), Scope: scopeOf(plan), Limit: plan.Limit, Complexity: plan.Score,
	}, nil
}

func (s *Service) plan(ctx context.Context, c Caller, text string) (*querylang.Plan, error) {
	q, err := querylang.Parse(text)
	if err != nil {
		return nil, err
	}
	pr, err := s.principal(ctx, c)
	if err != nil {
		return nil, err
	}
	return querylang.Build(q, text, pr, querylang.BuildOptions{Now: s.now})
}

// principal resolves the caller on the server. It fails closed: a
// member's query with no data scope enforcer, or a failed scope lookup,
// is an error.
func (s *Service) principal(ctx context.Context, c Caller) (querylang.Principal, error) {
	var pr querylang.Principal
	tenantID, err := shared.IDFromString(c.TenantID)
	if err != nil {
		return pr, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	var userID shared.ID
	if c.UserID != "" {
		if userID, err = shared.IDFromString(c.UserID); err != nil {
			return pr, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	var scope *shared.DataScope
	switch {
	case !c.IsAdmin:
		// A member, or a user-less API key (its scope has no rows).
		if s.dataScope == nil {
			return pr, errors.New("data scope enforcer not configured")
		}
		scope, err = s.dataScope.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, APIKey: c.APIKey})
		if err == nil && scope == nil {
			return pr, errors.New("data scope did not resolve")
		}
	case c.UserID != "" && s.dataScope != nil:
		// Private program assets stay hidden from administrators who are
		// neither owners nor members.
		scope, err = s.dataScope.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: true,
			IsOwner: s.dataScope.CallerOf(ctx).IsOwner, APIKey: c.APIKey})
	}
	if err != nil {
		return pr, fmt.Errorf("resolve data scope: %w", err)
	}
	return querylang.Principal{TenantID: tenantID, UserID: userID, Admin: c.IsAdmin, Scope: scope, Has: c.Has}, nil
}

// Cost class bounds, in planner cost units.
const (
	lowCost    = 10_000
	mediumCost = 1_000_000
)

func costClass(e querylang.Estimate) string {
	switch {
	case e.Cost < lowCost:
		return "low"
	case e.Cost < mediumCost:
		return "medium"
	}
	return "high"
}

func scopeOf(p *querylang.Plan) Scope {
	sc := Scope{Kind: "organization"}
	if p.Restricted() {
		sc.Kind = "data_scope"
		sc.Rules = append(sc.Rules, "only "+p.Entity().Noun+" in your data scope")
	} else if p.Principal().Scope != nil {
		sc.Rules = append(sc.Rules, "private bug-bounty program assets you are not a member of are left out")
	}
	if p.MemberRule() {
		sc.Rules = append(sc.Rules, "pentest findings only from campaigns you are a member of")
	}
	for _, m := range p.Entity().MandatoryFilters() {
		sc.Rules = append(sc.Rules, m.Why)
	}
	return sc
}

// limiter bounds concurrent queries per user, per tenant and in total (one
// API process; each replica has its own).
type limiter struct {
	mu        sync.Mutex
	perUser   int
	perTenant int
	total     int
	running   int
	users     map[string]int
	tenants   map[string]int
}

func newLimiter(perUser, perTenant, total int) *limiter {
	return &limiter{perUser: perUser, perTenant: perTenant, total: total, users: map[string]int{}, tenants: map[string]int{}}
}

func (l *limiter) acquire(tenantID, userID string) (func(), error) {
	uk := tenantID + "/" + userID
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.users[uk] >= l.perUser || l.tenants[tenantID] >= l.perTenant || l.running >= l.total {
		return nil, ErrBusy
	}
	l.running++
	l.users[uk]++
	l.tenants[tenantID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.running--
			if l.users[uk]--; l.users[uk] <= 0 {
				delete(l.users, uk)
			}
			if l.tenants[tenantID]--; l.tenants[tenantID] <= 0 {
				delete(l.tenants, tenantID)
			}
		})
	}, nil
}
