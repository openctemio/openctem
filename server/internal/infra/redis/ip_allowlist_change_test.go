package redis

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIPAllowlistChangeBusInvalidatesEveryReplica(t *testing.T) {
	rc := testRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cacheA, cacheB := &recordingCache{}, &recordingCache{}
	modCache := &recordingCache{}
	a := newCacheInvalidationBus(rc, IPAllowlistChangeChannel, cacheA, logger.NewNop())
	b := newCacheInvalidationBus(rc, IPAllowlistChangeChannel, cacheB, logger.NewNop())
	mod := newModuleChangeBus(rc, modCache, logger.NewNop())
	for _, bus := range []*CacheInvalidationBus{a, b, mod} {
		if err := bus.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}

	tid := shared.NewID().String()
	a.Invalidate(tid)
	waitFor(t, func() bool { return len(cacheB.snapshot()) == 1 })
	if got := cacheB.snapshot(); got[0] != tid {
		t.Fatalf("replica B dropped %v, want %s", got, tid)
	}
	time.Sleep(200 * time.Millisecond)
	if got := cacheA.snapshot(); len(got) != 1 || got[0] != tid {
		t.Fatalf("origin dropped %v, want exactly one drop of %s", got, tid)
	}
	// Channels are separate: an allowlist change never touches module caches.
	if got := modCache.snapshot(); len(got) != 0 {
		t.Fatalf("module cache dropped by an allowlist change: %v", got)
	}

	// Redis carries only hints: malformed, oversized and non-UUID messages
	// are dropped.
	for _, bad := range []string{`not json`, `{"o":"x","t":"../etc"}`, `{"o":"x","t":""}`,
		`{"o":"x","t":"` + string(make([]byte, 300)) + `"}`} {
		if err := rc.Publish(ctx, IPAllowlistChangeChannel, bad).Err(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if got := cacheB.snapshot(); len(got) != 1 {
		t.Fatalf("a malformed change was applied: %v", got)
	}
}
