package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// DisabledModuleProvider supplies the modules that are off for a tenant.
// Implemented by *module.ModuleService.
type DisabledModuleProvider interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// ModuleStateProvider also says why each module is off (not_entitled,
// unavailable, disabled_by_admin). *module.ModuleService implements it; a
// provider without it reports every off module as disabled_by_admin.
type ModuleStateProvider interface {
	TenantModuleStates(ctx context.Context, tenantID string) map[string]string
}

// ModuleGate answers "is module X on for tenant Y" for per-tenant route
// gating, with a short-TTL cache dropped on every replica by a module change
// (RFC-064). The organization's own switches are preferences; its plan and
// the administrator grants are entitlements, read fail-closed by the provider
// (an entitlement that cannot be read makes every non-core module
// unavailable: 503). With no gate, provider or tenant the request passes;
// permissions remain the authorization boundary.
type ModuleGate struct {
	provider DisabledModuleProvider
	ttl      time.Duration
	mu       sync.RWMutex
	cache    map[string]cachedStates
}

type cachedStates struct {
	states map[string]string // module id -> reason it is off
	expiry time.Time
}

// NewModuleGate constructs a gate. A zero ttl defaults to 60s.
func NewModuleGate(provider DisabledModuleProvider, ttl time.Duration) *ModuleGate {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &ModuleGate{provider: provider, ttl: ttl, cache: make(map[string]cachedStates)}
}

// IsEnabled reports whether moduleID is on for the tenant. A nil gate,
// missing provider, empty tenant or core module resolve to true.
func (g *ModuleGate) IsEnabled(ctx context.Context, tenantID, moduleID string) bool {
	return g.offReason(ctx, tenantID, moduleID) == ""
}

// offReason is why the module is off for the tenant ("" when it is on).
func (g *ModuleGate) offReason(ctx context.Context, tenantID, moduleID string) string {
	if g == nil || g.provider == nil || tenantID == "" || moduledom.IsCoreModule(moduleID) {
		return ""
	}
	return g.states(ctx, tenantID)[moduleID]
}

func (g *ModuleGate) states(ctx context.Context, tenantID string) map[string]string {
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[tenantID]; ok && now.Before(e.expiry) {
		g.mu.RUnlock()
		return e.states
	}
	g.mu.RUnlock()

	var states map[string]string
	if sp, ok := g.provider.(ModuleStateProvider); ok {
		states = sp.TenantModuleStates(ctx, tenantID)
	} else {
		states = map[string]string{}
		for id, off := range g.provider.TenantDisabledModules(ctx, tenantID) {
			if off {
				states[id] = ModuleReasonDisabled
			}
		}
	}
	ttl := g.ttl
	if hasUnavailable(states) {
		// An entitlement read failure is retried soon, not held for the TTL.
		ttl = 5 * time.Second
	}
	g.mu.Lock()
	g.cache[tenantID] = cachedStates{states: states, expiry: now.Add(ttl)}
	g.mu.Unlock()
	return states
}

func hasUnavailable(states map[string]string) bool {
	for _, r := range states {
		if r == ModuleReasonUnavailable {
			return true
		}
	}
	return false
}

// Invalidate drops a tenant's cached state — call after a module or
// entitlement change so it takes effect immediately rather than after the TTL.
func (g *ModuleGate) Invalidate(tenantID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}

// InvalidateAll drops every tenant's cached state (a plan mapping change).
func (g *ModuleGate) InvalidateAll() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.cache = make(map[string]cachedStates)
	g.mu.Unlock()
}

// Reasons a module is off (MODULE_NOT_ENABLED details.reason).
const (
	// ModuleReasonDisabled: the organization switched the module off.
	ModuleReasonDisabled = "disabled_by_admin"
	// ModuleReasonNotEntitled: the organization's plan does not include it,
	// or a platform administrator denied it.
	ModuleReasonNotEntitled = "not_entitled"
	// ModuleReasonUnavailable: the entitlement could not be read (503).
	ModuleReasonUnavailable = "unavailable"
)

// ModuleNotEnabledDetails is the details object of a MODULE_NOT_ENABLED error:
// which module, and why, so a client can say "turned off by your
// organization" or "not in your plan" rather than guess. Module ids are
// public product facts.
type ModuleNotEnabledDetails struct {
	Module string `json:"module"`
	Reason string `json:"reason"`
}

// RequireModule returns middleware that blocks a route group when the module is
// off for the requesting tenant: 403 MODULE_NOT_ENABLED with the reason, or
// 503 when the entitlement could not be read.
func (g *ModuleGate) RequireModule(moduleID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reason := g.offReason(r.Context(), GetTenantID(r.Context()), moduleID)
			switch reason {
			case "":
				next.ServeHTTP(w, r)
			case ModuleReasonUnavailable:
				apierror.ServiceUnavailable("This feature cannot be checked against your plan right now; try again shortly").
					WithDetails(ModuleNotEnabledDetails{Module: moduleID, Reason: reason}).
					WriteJSON(w)
			default:
				msg := "This module is not enabled for your team"
				if reason == ModuleReasonNotEntitled {
					msg = "This module is not included in your organization's plan"
				}
				apierror.ModuleNotEnabled(msg).
					WithDetails(ModuleNotEnabledDetails{Module: moduleID, Reason: reason}).
					WriteJSON(w)
			}
		})
	}
}
