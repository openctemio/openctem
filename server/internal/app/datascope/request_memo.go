package datascope

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Request memo: one HTTP request asks the same data-scope questions several
// times (the route guard checks the finding, then the service checks it
// again and resolves the caller's scope for its own reads). The memo keeps
// the answers for that one request so each question costs its queries once.
//
// Security: the memo lives only in the request's context; nothing is shared
// between requests, users or tenants. Every key carries the tenant and the
// whole Caller (user, admin, owner, API key), so a different caller or
// tenant in the same context never reads another's answer. Only a resolved
// scope and an "allowed" verdict are kept: a refusal or a lookup error is
// asked again (it stays fail closed either way). A context that outlives
// its request (a goroutine started from it) stops using the memo after
// memoMaxAge, so a revoked role is seen by later work.

// memoMaxAge bounds how long a request's answers are reused.
const memoMaxAge = 10 * time.Second

type memoCtxKey struct{}

type scopeKey struct {
	tenant shared.ID
	caller Caller
}

type verdictKind uint8

const (
	verdictAsset verdictKind = iota + 1
	verdictFinding
	verdictFindingCampaign
)

type verdictKey struct {
	kind   verdictKind
	tenant shared.ID
	id     shared.ID
	caller Caller
}

// inScopeKey is one "asset inside this scope" answer; the scope's fields
// are its whole identity.
type inScopeKey struct {
	tenant       shared.ID
	user         shared.ID
	unrestricted bool
	asset        shared.ID
}

type scopeEntry struct {
	scope *shared.DataScope // nil: unrestricted
}

type requestMemo struct {
	created time.Time
	mu      sync.Mutex
	scopes  map[scopeKey]scopeEntry
	allowed map[verdictKey]struct{}
	inScope map[inScopeKey]struct{}
}

// WithRequestMemo returns a context that memoizes this request's data-scope
// answers. It returns ctx unchanged when it already carries a memo.
func WithRequestMemo(ctx context.Context) context.Context {
	if _, ok := ctx.Value(memoCtxKey{}).(*requestMemo); ok {
		return ctx
	}
	return context.WithValue(ctx, memoCtxKey{}, &requestMemo{
		created: time.Now(),
		scopes:  map[scopeKey]scopeEntry{},
		allowed: map[verdictKey]struct{}{},
		inScope: map[inScopeKey]struct{}{},
	})
}

// WithRequestMemo installs the request memo (see the package function); it
// lets the HTTP guard install it through its interface.
func (e *Enforcer) WithRequestMemo(ctx context.Context) context.Context {
	return WithRequestMemo(ctx)
}

// memoOf returns the context's live memo, or nil.
func memoOf(ctx context.Context) *requestMemo {
	m, ok := ctx.Value(memoCtxKey{}).(*requestMemo)
	if !ok || time.Since(m.created) > memoMaxAge {
		return nil
	}
	return m
}

// copyScope returns a copy so a caller changing the scope it got cannot
// change the memo's answer.
func copyScope(s *shared.DataScope) *shared.DataScope {
	if s == nil {
		return nil
	}
	c := *s
	return &c
}

func (m *requestMemo) scope(k scopeKey) (*shared.DataScope, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.scopes[k]
	if !ok {
		return nil, false
	}
	return copyScope(e.scope), true
}

func (m *requestMemo) putScope(k scopeKey, s *shared.DataScope) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scopes[k] = scopeEntry{scope: copyScope(s)}
}

func (m *requestMemo) isAllowed(k verdictKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.allowed[k]
	return ok
}

func (m *requestMemo) allow(k verdictKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowed[k] = struct{}{}
}

func (m *requestMemo) isInScope(k inScopeKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.inScope[k]
	return ok
}

func (m *requestMemo) putInScope(k inScopeKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inScope[k] = struct{}{}
}

// memoVerdict runs check unless the request already got "allowed" for the
// same question, and remembers an "allowed" answer.
func (e *Enforcer) memoVerdict(ctx context.Context, kind verdictKind, tenantID, id shared.ID, check func() error) error {
	m := memoOf(ctx)
	if m == nil {
		return check()
	}
	k := verdictKey{kind: kind, tenant: tenantID, id: id, caller: e.CallerOf(ctx)}
	if m.isAllowed(k) {
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	m.allow(k)
	return nil
}
