package tool

import (
	"context"
	"sync"
)

// Per-operation memo for ToolAvailability (docs/architecture/tool-availability.md).
//
// One decision (a scan trigger, a workflow preview, a coverage planner tick)
// asks for the availability of several tools; each ask used to recompute the
// whole tenant view. WithAvailabilityMemo lets the operation compute it once.
// The memo lives in the context of that one operation: it is never shared
// across requests or tenants and has no TTL, so the next decision reads fresh
// data. Results are read-only for callers.

type availabilityMemoKey struct{}

type availabilityMemo struct {
	mu      sync.Mutex
	results map[string]*ToolAvailabilityResult
}

// WithAvailabilityMemo returns a context whose ToolAvailability calls reuse
// one result per tenant and zone. A context that already carries a memo is
// returned unchanged, so nested operations share the outer one.
func WithAvailabilityMemo(ctx context.Context) context.Context {
	if ctx.Value(availabilityMemoKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, availabilityMemoKey{}, &availabilityMemo{results: map[string]*ToolAvailabilityResult{}})
}

func availabilityMemoFrom(ctx context.Context) *availabilityMemo {
	m, _ := ctx.Value(availabilityMemoKey{}).(*availabilityMemo)
	return m
}

// memoKey includes the tenant and the zone: one memo can never answer for
// another tenant's or zone's view. The NUL separator cannot occur in an id.
func memoKey(tenantID, zoneID string) string { return tenantID + "\x00" + zoneID }

func (m *availabilityMemo) get(key string) *ToolAvailabilityResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.results[key]
}

func (m *availabilityMemo) put(key string, r *ToolAvailabilityResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[key] = r
}
