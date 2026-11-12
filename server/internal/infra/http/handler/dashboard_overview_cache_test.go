package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func overviewReq(tenant, user, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, user)
	return r.WithContext(ctx)
}

// A caller's overview is reused within the TTL; another user, another
// tenant or another session of the same user never gets it.
func TestDashboardOverview_ReusesOnlyTheSameCallersResult(t *testing.T) {
	var hits atomic.Int64
	router := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	h := NewDashboardOverviewHandler(func() http.Handler { return router }, logger.NewNop())
	n := int64(len(DashboardOverviewParts))
	call := func(tenant, user, token string) {
		rec := httptest.NewRecorder()
		h.Overview(rec, overviewReq(tenant, user, token))
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("status %d, cache-control %q", rec.Code, rec.Header().Get("Cache-Control"))
		}
	}
	call("t1", "u1", "a")
	call("t1", "u1", "a")
	if hits.Load() != n {
		t.Fatalf("parts dispatched %d, want %d (second call served from the cache)", hits.Load(), n)
	}
	call("t1", "u2", "b") // another user of the same tenant
	call("t2", "u1", "c") // the same user in another tenant
	call("t1", "u1", "d") // another session of the same user
	if hits.Load() != 4*n {
		t.Fatalf("parts dispatched %d, want %d: a result was shared across callers", hits.Load(), 4*n)
	}
}

// One tenant never runs more than overviewTenantParts parts at once, however
// many of its users load the dashboard together; another tenant is not held
// back by it.
func TestDashboardOverview_CapsPartsPerTenant(t *testing.T) {
	var cur, peak atomic.Int64
	router := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		cur.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	h := NewDashboardOverviewHandler(func() http.Handler { return router }, logger.NewNop())
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h.Overview(httptest.NewRecorder(), overviewReq("t1", "u"+string(rune('a'+i)), "tok"))
		}(i)
	}
	wg.Wait()
	if peak.Load() > overviewTenantParts {
		t.Fatalf("peak parts in flight for one tenant = %d, want <= %d", peak.Load(), overviewTenantParts)
	}
}
