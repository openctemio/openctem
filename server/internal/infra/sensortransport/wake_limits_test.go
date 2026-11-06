package sensortransport

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// A tenant releasing or refusing commands in a loop wakes every stream of
// the tenant each time. The hub delivers at most one tenant wake per
// WakeCoalesce, and the last wake of a flood is still delivered
// (research/84 RE-12).
func TestHub_TenantWakeFloodIsBoundedAndNeverLost(t *testing.T) {
	h := NewHub(4)
	st, err := h.add("t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	var delivered atomic.Int32
	var lastAt atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-st.wake:
				delivered.Add(1)
				lastAt.Store(time.Now().UnixNano())
			}
		}
	}()
	defer close(stop)

	// ~1.2 s of wakes, one per millisecond: unbounded, every one of them
	// would reach the stream (the consumer drains at once).
	start := time.Now()
	var lastCall time.Time
	for time.Since(start) < 1200*time.Millisecond {
		lastCall = time.Now()
		h.Wake("t1", "")
		time.Sleep(time.Millisecond)
	}
	time.Sleep(WakeCoalesce + 200*time.Millisecond)

	// 1.2 s / 500 ms: the first at once, then one per interval, plus the
	// trailing one.
	if n := delivered.Load(); n < 2 || n > 5 {
		t.Fatalf("delivered %d wakes for a flood of ~1000, want 2..5", n)
	}
	if lastAt.Load() < lastCall.UnixNano() {
		t.Fatal("the flood's last wake was not delivered after it (a folded wake must be delayed, never lost)")
	}
}

// countingHints counts doorbell reads (database work of a stream).
type countingHints struct{ n atomic.Int32 }

func (c *countingHints) StreamHints(context.Context, []string) handler.StreamHints {
	c.n.Add(1)
	return handler.StreamHints{Status: "ok"}
}

// A sensor may open StreamOpenBurst control streams at once; the next open
// in the burst is refused with ResourceExhausted before any database work,
// even though the concurrent bound would admit it. Another sensor is not
// affected.
func TestSubscribe_OpenRateLimitedPerSensor(t *testing.T) {
	s := NewServer(Config{StreamOpenBurst: 3, StreamOpensPerMinute: 1, MaxStreamsPerSensor: 10}, nil, logger.NewNop())
	hints := &countingHints{}
	s.Attach(&fakeV2{status: 200}, hints, sameAuth{})
	id := tenantSensor()
	client := serve(t, s, &id)

	open := func(c interface {
		Subscribe(context.Context, *connect.Request[sensorv3.SubscribeRequest]) (*connect.ServerStreamForClient[sensorv3.SubscribeResponse], error)
	}) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := c.Subscribe(ctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		if !st.Receive() {
			return st.Err()
		}
		return nil
	}
	for i := range 3 {
		if err := open(client); err != nil {
			t.Fatalf("open %d within the burst: %v", i+1, err)
		}
	}
	before := hints.n.Load()
	err := open(client)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("open 4 in the burst: %v, want ResourceExhausted", err)
	}
	if hints.n.Load() != before {
		t.Fatal("a refused open read the doorbell")
	}
	other := tenantSensor()
	if err := open(serve(t, s, &other)); err != nil {
		t.Fatalf("another sensor was refused: %v", err)
	}
}
