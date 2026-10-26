package feedsync

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestTrigger_ReturnsAtOnceAndRunsOnce(t *testing.T) {
	release := make(chan struct{})
	var runs atomic.Int32
	started := make(chan struct{}, 4)
	r := New(map[string]Job{"kev": func(ctx context.Context) error {
		runs.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}}, logger.NewNop())

	begin := time.Now()
	out, err := r.Trigger("kev")
	if err != nil || out != Queued {
		t.Fatalf("first: %v %v", out, err)
	}
	if time.Since(begin) > time.Second {
		t.Fatalf("the request waited for the job: %v", time.Since(begin))
	}
	<-started
	// A second request while the job runs is acknowledged, not started.
	if out, err := r.Trigger("kev"); err != nil || out != AlreadyRunning {
		t.Fatalf("second: %v %v", out, err)
	}
	close(release)
	r.Shutdown(context.Background())
	if runs.Load() != 1 {
		t.Fatalf("job ran %d times", runs.Load())
	}
}

func TestTrigger_RateLimitAndUnknown(t *testing.T) {
	now := time.Now()
	r := New(map[string]Job{"epss": func(context.Context) error { return nil }}, logger.NewNop())
	r.now = func() time.Time { return now }
	if _, err := r.Trigger("nope"); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("unknown: %v", err)
	}
	if out, err := r.Trigger("epss"); err != nil || out != Queued {
		t.Fatalf("first: %v %v", out, err)
	}
	r.Shutdown(context.Background())
	var tooSoon *TooSoonError
	if _, err := r.Trigger("epss"); !errors.As(err, &tooSoon) || tooSoon.RetryAfter <= 0 {
		t.Fatalf("second inside the gap: %v", err)
	}
	now = now.Add(DefaultMinGap + time.Second)
	if out, err := r.Trigger("epss"); err != nil || out != Queued {
		t.Fatalf("after the gap: %v %v", out, err)
	}
}

func TestTrigger_AJobThatPanicsFreesTheFeed(t *testing.T) {
	r := New(map[string]Job{"kev": func(context.Context) error { panic("boom") }}, logger.NewNop())
	r.minGap = 0
	if _, err := r.Trigger("kev"); err != nil {
		t.Fatal(err)
	}
	r.wg.Wait()
	if out, err := r.Trigger("kev"); err != nil || out != Queued {
		t.Fatalf("after panic: %v %v", out, err)
	}
	r.Shutdown(context.Background())
}
