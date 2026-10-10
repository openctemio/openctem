package redis

import (
	"context"
	"sync"
	"testing"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingCache records the tenants whose module cache one replica dropped.
type recordingCache struct {
	mu      sync.Mutex
	tenants []string
}

func (c *recordingCache) Invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenants = append(c.tenants, tenantID)
}

func (c *recordingCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenants = append(c.tenants, "*")
}

func (c *recordingCache) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.tenants...)
}

func TestModuleChangeBusInvalidatesEveryReplica(t *testing.T) {
	rc := testRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cacheA, cacheB := &recordingCache{}, &recordingCache{}
	a := newModuleChangeBus(rc, cacheA, logger.NewNop())
	b := newModuleChangeBus(rc, cacheB, logger.NewNop())
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}

	tid := shared.NewID().String()
	a.Invalidate(tid)
	waitFor(t, func() bool { return len(cacheB.snapshot()) == 1 })
	if got := cacheB.snapshot(); got[0] != tid {
		t.Fatalf("replica B dropped %v, want %s", got, tid)
	}
	// The origin dropped its own cache directly, once.
	time.Sleep(200 * time.Millisecond)
	if got := cacheA.snapshot(); len(got) != 1 || got[0] != tid {
		t.Fatalf("replica A dropped %v", got)
	}

	// A plan mapping change drops every tenant on every replica.
	a.InvalidateAll()
	waitFor(t, func() bool { return len(cacheB.snapshot()) == 2 })
	if got := cacheB.snapshot(); got[1] != "*" {
		t.Fatalf("replica B got %v after InvalidateAll", got)
	}

	// Redis carries only hints: malformed or non-UUID messages are dropped.
	for _, bad := range []string{`not json`, `{"o":"x","t":"../etc"}`, `{"o":"x","t":""}`,
		`{"o":"x","t":"` + string(make([]byte, 300)) + `"}`} {
		if err := rc.Publish(ctx, ModuleChangeChannel, bad).Err(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if got := cacheB.snapshot(); len(got) != 2 {
		t.Fatalf("a malformed change was applied: %v", got)
	}
}

func TestModuleChangeBusNeverBlocks(t *testing.T) {
	// Not started: the queue fills and further changes are dropped, the
	// local cache is still dropped every time.
	cache := &recordingCache{}
	bus := newModuleChangeBus(redislib.NewClient(&redislib.Options{Addr: "127.0.0.1:1"}), cache, logger.NewNop())
	done := make(chan struct{})
	go func() {
		for range moduleChangeQueue * 2 {
			bus.Invalidate(shared.NewID().String())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Invalidate blocked")
	}
	if got := cache.snapshot(); len(got) != moduleChangeQueue*2 {
		t.Fatalf("local invalidations %d", len(got))
	}
}
