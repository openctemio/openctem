package safego

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRun_RecoversAndCounts(t *testing.T) {
	before := testutil.ToFloat64(metrics.PanicsRecoveredTotal.WithLabelValues("safego-test"))
	err := Run(logger.NewNop(), "safego-test", func() { panic("boom") })
	if !errors.Is(err, ErrPanic) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run = %v, want an ErrPanic naming the value", err)
	}
	if got := testutil.ToFloat64(metrics.PanicsRecoveredTotal.WithLabelValues("safego-test")) - before; got != 1 {
		t.Fatalf("panics recovered = %v, want 1", got)
	}
	if err := Run(nil, "safego-test", func() {}); err != nil {
		t.Fatalf("Run without a panic = %v", err)
	}
}

func TestRun_CapsTheValueOnACharacterBoundary(t *testing.T) {
	err := Run(nil, "safego-test", func() { panic(strings.Repeat("ệ", 400)) })
	msg := err.Error()
	if !utf8.ValidString(msg) || len(msg) > maxPanicValue+64 {
		t.Fatalf("capped panic value: %d bytes, valid=%v", len(msg), utf8.ValidString(msg))
	}
}

func TestGo_PanicDoesNotKillTheProcess(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	Go(logger.NewNop(), "safego-test", func() {
		defer wg.Done()
		panic(errors.New("boom"))
	})
	wg.Wait()
}
