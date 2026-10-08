package redis

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingHub records the wakes delivered to one replica.
type recordingHub struct {
	mu    sync.Mutex
	wakes []string
	all   int
}

func (h *recordingHub) Wake(t, s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wakes = append(h.wakes, t+"/"+s)
}

func (h *recordingHub) WakeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.all++
}

func (h *recordingHub) snapshot() ([]string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.wakes...), h.all
}

func testRedis(t *testing.T) redislib.UniversalClient {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}
	rc := redislib.NewClient(&redislib.Options{Addr: net.JoinHostPort(host, port), Password: os.Getenv("REDIS_PASSWORD")})
	if err := rc.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 2s")
}

func TestSensorWakeBusFansOutAcrossReplicas(t *testing.T) {
	rc := testRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hubA, hubB := &recordingHub{}, &recordingHub{}
	a := newSensorWakeBus(rc, hubA, logger.NewNop())
	b := newSensorWakeBus(rc, hubB, logger.NewNop())
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}

	tid, sid := shared.NewID().String(), shared.NewID().String()
	a.Wake(tid, sid)
	waitFor(t, func() bool { w, _ := hubB.snapshot(); return len(w) == 1 })
	if w, _ := hubB.snapshot(); w[0] != tid+"/"+sid {
		t.Fatalf("replica B got %v", w)
	}
	// The origin woke its own hub directly, once: its own message is not
	// delivered back.
	time.Sleep(200 * time.Millisecond)
	if w, _ := hubA.snapshot(); len(w) != 1 {
		t.Fatalf("replica A woken %d times", len(w))
	}

	b.WakeAll()
	waitFor(t, func() bool { _, n := hubA.snapshot(); return n == 1 })

	// Redis carries only hints: malformed or non-UUID messages are dropped.
	for _, bad := range []string{`not json`, `{"o":"x","t":"../etc"}`, `{"o":"x","t":"` + tid + `","s":"x y"}`,
		`{"o":"x","t":"` + string(make([]byte, 600)) + `"}`} {
		if err := rc.Publish(ctx, SensorWakeChannel, bad).Err(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if w, _ := hubB.snapshot(); len(w) != 1 {
		t.Fatalf("a malformed wake was delivered: %v", w)
	}
}

func TestSensorWakeBusNeverBlocks(t *testing.T) {
	// Not started: the queue fills and further wakes are dropped, the local
	// hub is still woken every time.
	hub := &recordingHub{}
	bus := newSensorWakeBus(redislib.NewClient(&redislib.Options{Addr: "127.0.0.1:1"}), hub, logger.NewNop())
	done := make(chan struct{})
	go func() {
		for range sensorWakeQueue * 2 {
			bus.Wake(shared.NewID().String(), "")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake blocked")
	}
	if w, _ := hub.snapshot(); len(w) != sensorWakeQueue*2 {
		t.Fatalf("local wakes %d", len(w))
	}
}
