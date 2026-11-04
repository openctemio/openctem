package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// snapProvider scripts the snapshot a gate reads.
type snapProvider struct {
	states     map[string]string
	validUntil time.Time
	cacheable  bool
	calls      int
	onRead     func() // runs inside a read, to model a change racing a read
}

func (p *snapProvider) TenantDisabledModules(ctx context.Context, t string) map[string]bool {
	return nil
}

func (p *snapProvider) TenantModuleStateSnapshot(_ context.Context, _ string) (map[string]string, time.Time, bool) {
	p.calls++
	if p.onRead != nil {
		p.onRead()
	}
	return p.states, p.validUntil, p.cacheable
}

// An entitlement that could not be read reports every module unavailable. That
// answer is returned (fail closed) but never kept: the next request reads
// again, so recovery is seen at once, not after a TTL.
func TestModuleGate_FailedReadIsNotCached(t *testing.T) {
	p := &snapProvider{states: map[string]string{"pentest": ModuleReasonUnavailable}, cacheable: false}
	g := NewModuleGate(p, time.Minute)
	ctx := context.Background()
	if g.IsEnabled(ctx, "t1", "pentest") {
		t.Fatal("an unreadable entitlement must fail closed")
	}
	p.states, p.cacheable = map[string]string{}, true // the reader recovered
	if !g.IsEnabled(ctx, "t1", "pentest") {
		t.Fatal("the failure was kept: a recovered entitlement still reads as off")
	}
	if p.calls != 2 {
		t.Fatalf("expected a fresh read after the failure, got %d reads", p.calls)
	}
}

// A read-only grace that ends by itself must not outlive the cache.
func TestModuleGate_GraceEndShortensTheCache(t *testing.T) {
	p := &snapProvider{
		states:     map[string]string{"pentest": ModuleReasonReadOnlyGrace},
		validUntil: time.Now().Add(150 * time.Millisecond),
		cacheable:  true,
	}
	g := NewModuleGate(p, time.Hour)
	ctx := context.Background()
	if !g.IsReadable(ctx, "t1", "pentest") || g.IsEnabled(ctx, "t1", "pentest") {
		t.Fatal("in grace the module is readable and not writable")
	}
	p.states, p.validUntil = map[string]string{"pentest": ModuleReasonNotEntitled}, time.Time{}
	time.Sleep(200 * time.Millisecond)
	if g.IsReadable(ctx, "t1", "pentest") {
		t.Fatal("the grace ended but the cached state still lets reads through")
	}
}

// An answer already past its end is not kept at all.
func TestModuleGate_ExpiredAnswerIsNotKept(t *testing.T) {
	p := &snapProvider{states: map[string]string{}, validUntil: time.Now().Add(-time.Second), cacheable: true}
	g := NewModuleGate(p, time.Hour)
	g.IsEnabled(context.Background(), "t1", "pentest")
	g.IsEnabled(context.Background(), "t1", "pentest")
	if p.calls != 2 {
		t.Fatalf("an answer that is already out of date was cached (%d reads)", p.calls)
	}
}

// A read that started before a toggle must not store its answer after the
// toggle's invalidation.
func TestModuleGate_InvalidationDuringReadWins(t *testing.T) {
	p := &snapProvider{states: map[string]string{}, cacheable: true}
	g := NewModuleGate(p, time.Hour)
	ctx := context.Background()
	p.onRead = func() {
		p.onRead = nil
		g.Invalidate("t1") // the toggle lands while the read is in flight
	}
	g.IsEnabled(ctx, "t1", "pentest") // read the old state
	p.states = map[string]string{"pentest": ModuleReasonDisabled}
	if g.IsEnabled(ctx, "t1", "pentest") {
		t.Fatal("a pre-toggle answer was stored after the invalidation")
	}
}

// An installation-wide module the platform has off answers 403
// MODULE_NOT_ENABLED "disabled by the platform", not a 404.
func TestRequireModule_DisabledByPlatform(t *testing.T) {
	p := &snapProvider{states: map[string]string{"pentest": ModuleReasonDisabledByPlatform}, cacheable: true}
	g := NewModuleGate(p, time.Minute)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.WithValue(context.Background(), TenantIDKey, "t1"), http.MethodGet, "/x", nil)
	g.RequireModule("pentest")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran for a module the platform disabled")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "MODULE_NOT_ENABLED") ||
		!strings.Contains(rec.Body.String(), "disabled by the platform") ||
		!strings.Contains(rec.Body.String(), ModuleReasonDisabledByPlatform) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
