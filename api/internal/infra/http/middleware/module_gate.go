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

// ModuleSnapshotProvider is a ModuleStateProvider that also says how long its
// answer can be kept: validUntil is the next moment the state changes by
// itself (zero: none), cacheable is false when a read failed.
// *module.ModuleService implements it.
type ModuleSnapshotProvider interface {
	TenantModuleStateSnapshot(ctx context.Context, tenantID string) (states map[string]string, validUntil time.Time, cacheable bool)
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
	// gen counts invalidations: a read that started before an invalidation
	// must not store its (then stale) answer after it.
	gen uint64
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

// IsReadable reports whether the module's data may be read for the tenant:
// on, or in its read-only grace (reads pass, as RequireModule lets a safe
// method through). The dashboard uses it for widgets of a module.
func (g *ModuleGate) IsReadable(ctx context.Context, tenantID, moduleID string) bool {
	switch g.offReason(ctx, tenantID, moduleID) {
	case "", ModuleReasonReadOnlyGrace:
		return true
	}
	return false
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
	gen := g.gen
	g.mu.RUnlock()

	var states map[string]string
	ttl := g.ttl
	cacheable := true
	if snap, ok := g.provider.(ModuleSnapshotProvider); ok {
		var validUntil time.Time
		states, validUntil, cacheable = snap.TenantModuleStateSnapshot(ctx, tenantID)
		// A grace or a timed deny that ends by itself changes the state with no
		// write to tell us: never keep the answer past it.
		if !validUntil.IsZero() {
			if d := validUntil.Sub(now); d < ttl {
				ttl = d
			}
		}
	} else if sp, ok := g.provider.(ModuleStateProvider); ok {
		states = sp.TenantModuleStates(ctx, tenantID)
		cacheable = !hasUnavailable(states)
	} else {
		states = map[string]string{}
		for id, off := range g.provider.TenantDisabledModules(ctx, tenantID) {
			if off {
				states[id] = ModuleReasonDisabled
			}
		}
	}
	// A failed read (entitlement unreadable: every module reported unavailable)
	// is the failure, not the organization's state: it is answered now, closed,
	// and never kept, so the next request reads again.
	if cacheable && ttl > 0 {
		g.mu.Lock()
		if g.gen == gen {
			g.cache[tenantID] = cachedStates{states: states, expiry: now.Add(ttl)}
		}
		g.mu.Unlock()
	}
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
	g.gen++
	g.mu.Unlock()
}

// InvalidateAll drops every tenant's cached state (a plan mapping change).
func (g *ModuleGate) InvalidateAll() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.gen++
	g.cache = make(map[string]cachedStates)
	g.mu.Unlock()
}

// Reasons a module is off (MODULE_NOT_ENABLED details.reason).
const (
	// ModuleReasonDisabled: the organization switched the module off.
	ModuleReasonDisabled = "disabled_by_admin"
	// ModuleReasonNotEntitled: the module is not available for this
	// organization (denied by the instance operator or a source).
	ModuleReasonNotEntitled = "not_entitled"
	// ModuleReasonUnavailable: the entitlement could not be read (503).
	ModuleReasonUnavailable = "unavailable"
	// ModuleReasonReadOnlyGrace: the organization lost the module recently:
	// reads (and export) pass, writes are refused.
	ModuleReasonReadOnlyGrace = "read_only_grace"
)

// ModuleNotEnabledDetails is the details object of a MODULE_NOT_ENABLED error:
// which module, and why, so a client can say "turned off by your
// organization" or "not available for this organization" rather than guess. Module ids are
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
			if reason == ModuleReasonReadOnlyGrace && isSafeMethod(r.Method) {
				reason = ""
			}
			switch reason {
			case "":
				next.ServeHTTP(w, r)
			case ModuleReasonUnavailable:
				apierror.ServiceUnavailable("This feature cannot be checked right now; try again shortly").
					WithDetails(ModuleNotEnabledDetails{Module: moduleID, Reason: reason}).
					WriteJSON(w)
			default:
				msg := "This module is not enabled for your team"
				switch reason {
				case ModuleReasonNotEntitled:
					msg = "This module is not available for this organization"
				case ModuleReasonReadOnlyGrace:
					msg = "This module is no longer available for this organization: it is read-only for now"
				}
				apierror.ModuleNotEnabled(msg).
					WithDetails(ModuleNotEnabledDetails{Module: moduleID, Reason: reason}).
					WriteJSON(w)
			}
		})
	}
}
