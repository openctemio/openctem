package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
	moduledom "github.com/openctemio/api/pkg/domain/module"
)

// DisabledModuleProvider supplies a tenant's explicitly-disabled module IDs.
// Implemented by *app.ModuleService.
type DisabledModuleProvider interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// ModuleGate answers "is module X enabled for tenant Y" for per-tenant route
// gating, with a short-TTL cache (module toggles are rare, so brief staleness is
// acceptable and this is a feature gate, not a security boundary). Fail-open in
// every uncertain case so it can never block legitimate traffic.
type ModuleGate struct {
	provider DisabledModuleProvider
	ttl      time.Duration
	mu       sync.RWMutex
	cache    map[string]cachedDisabled
}

type cachedDisabled struct {
	set    map[string]bool
	expiry time.Time
}

// NewModuleGate constructs a gate. A zero ttl defaults to 60s.
func NewModuleGate(provider DisabledModuleProvider, ttl time.Duration) *ModuleGate {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &ModuleGate{provider: provider, ttl: ttl, cache: make(map[string]cachedDisabled)}
}

// IsEnabled reports whether moduleID is enabled for the tenant. A nil gate,
// missing provider, empty tenant, core module, or lookup miss all resolve to
// true (fail-open) — only an explicitly-disabled non-core module returns false.
func (g *ModuleGate) IsEnabled(ctx context.Context, tenantID, moduleID string) bool {
	if g == nil || g.provider == nil || tenantID == "" {
		return true
	}
	if moduledom.IsCoreModule(moduleID) {
		return true
	}
	return !g.disabledSet(ctx, tenantID)[moduleID]
}

func (g *ModuleGate) disabledSet(ctx context.Context, tenantID string) map[string]bool {
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[tenantID]; ok && now.Before(e.expiry) {
		g.mu.RUnlock()
		return e.set
	}
	g.mu.RUnlock()

	set := g.provider.TenantDisabledModules(ctx, tenantID)
	g.mu.Lock()
	g.cache[tenantID] = cachedDisabled{set: set, expiry: now.Add(g.ttl)}
	g.mu.Unlock()
	return set
}

// Invalidate drops a tenant's cached set — call after a module toggle so the
// change takes effect immediately rather than after the TTL.
func (g *ModuleGate) Invalidate(tenantID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}

// RequireModule returns middleware that blocks a route group when the module is
// disabled for the requesting tenant. Fail-open (see IsEnabled): a nil gate or
// missing tenant lets the request through.
func (g *ModuleGate) RequireModule(moduleID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if g.IsEnabled(r.Context(), GetTenantID(r.Context()), moduleID) {
				next.ServeHTTP(w, r)
				return
			}
			apierror.ModuleNotEnabled("This module is not enabled for your team").WriteJSON(w)
		})
	}
}
