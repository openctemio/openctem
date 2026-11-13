package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSamplingHandler_Disabled(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	// Sampling disabled - should pass through all logs
	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled: false,
	})

	logger := slog.New(handler)

	for i := 0; i < 200; i++ {
		logger.Info("test message")
	}

	// Count log lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 200 {
		t.Errorf("expected 200 logs when sampling disabled, got %d", len(lines))
	}
}

func TestSamplingHandler_Threshold(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute, // Long tick to prevent reset during test
		Threshold: 10,
		Rate:      0.0, // Drop all after threshold
		ErrorRate: 1.0,
	})

	logger := slog.New(handler)

	// Log 100 identical messages
	for i := 0; i < 100; i++ {
		logger.Info("test message")
	}

	// Should only have threshold (10) logs
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 logs (threshold), got %d", len(lines))
	}
}

func TestSamplingHandler_Rate(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 10,
		Rate:      0.5, // 50% after threshold
		ErrorRate: 1.0,
	})

	logger := slog.New(handler)

	// Log 110 identical messages
	// First 10 should be logged (threshold)
	// Remaining 100 should be sampled at 50% = ~50 logs
	for i := 0; i < 110; i++ {
		logger.Info("test message")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 10 (threshold) + 50 (50% of 100) = 60
	// Allow some variance due to sampling algorithm
	if len(lines) < 55 || len(lines) > 65 {
		t.Errorf("expected ~60 logs (10 threshold + 50%% of 100), got %d", len(lines))
	}
}

func TestSamplingHandler_ErrorRate(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 5,
		Rate:      0.0, // Drop all info after threshold
		ErrorRate: 1.0, // Keep all errors
	})

	logger := slog.New(handler)

	// Log 50 info messages - only 5 should be logged
	for i := 0; i < 50; i++ {
		logger.Info("info message")
	}

	// Log 50 error messages - all should be logged (ErrorRate = 1.0)
	for i := 0; i < 50; i++ {
		logger.Error("error message")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 5 (info threshold) + 50 (all errors) = 55
	if len(lines) != 55 {
		t.Errorf("expected 55 logs (5 info + 50 errors), got %d", len(lines))
	}
}

func TestSamplingHandler_DifferentMessages(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 5,
		Rate:      0.0,
		ErrorRate: 1.0,
	})

	logger := slog.New(handler)

	// Log 10 of message A - only 5 should be logged
	for i := 0; i < 10; i++ {
		logger.Info("message A")
	}

	// Log 10 of message B - only 5 should be logged (separate counter)
	for i := 0; i < 10; i++ {
		logger.Info("message B")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 5 (A threshold) + 5 (B threshold) = 10
	if len(lines) != 10 {
		t.Errorf("expected 10 logs (5 each for A and B), got %d", len(lines))
	}
}

func TestSamplingHandler_CounterReset(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      50 * time.Millisecond, // Short tick for testing
		Threshold: 5,
		Rate:      0.0,
		ErrorRate: 1.0,
	})

	logger := slog.New(handler)

	// First batch - only 5 should be logged
	for i := 0; i < 10; i++ {
		logger.Info("test message")
	}

	// Wait for tick to reset counters
	time.Sleep(100 * time.Millisecond)

	// Second batch - another 5 should be logged (counter reset)
	for i := 0; i < 10; i++ {
		logger.Info("test message")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 5 (first batch) + 5 (second batch after reset) = 10
	if len(lines) != 10 {
		t.Errorf("expected 10 logs after counter reset, got %d", len(lines))
	}
}

func TestSamplingHandler_OnDropped(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	var droppedCount atomic.Int64

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 5,
		Rate:      0.0,
		ErrorRate: 1.0,
		OnDropped: func(ctx context.Context, record slog.Record) {
			droppedCount.Add(1)
		},
	})

	logger := slog.New(handler)

	// Log 20 messages - 5 logged, 15 dropped
	for i := 0; i < 20; i++ {
		logger.Info("test message")
	}

	if droppedCount.Load() != 15 {
		t.Errorf("expected 15 dropped logs, got %d", droppedCount.Load())
	}
}

func TestSamplingHandler_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 100,
		Rate:      0.1,
		ErrorRate: 1.0,
	})

	logger := slog.New(handler)

	// Concurrent logging from multiple goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				logger.Info("concurrent message")
			}
		}()
	}
	wg.Wait()

	// Just verify no panic/race occurred
	// The exact count depends on timing, but should be reasonable
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 100 || len(lines) > 200 {
		t.Errorf("unexpected log count in concurrent test: %d", len(lines))
	}
}

func TestSamplingHandler_WarnLevel(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 5,
		Rate:      0.0,
		ErrorRate: 1.0, // Warn and Error use ErrorRate
	})

	logger := slog.New(handler)

	// Log 20 warn messages - all should be logged (ErrorRate applies to Warn+)
	for i := 0; i < 20; i++ {
		logger.Warn("warn message")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 20 {
		t.Errorf("expected 20 warn logs (ErrorRate=1.0), got %d", len(lines))
	}
}

func TestDroppedLogsCounter(t *testing.T) {
	counter := NewDroppedLogsCounter()

	// Increment
	for i := 0; i < 10; i++ {
		counter.Increment(context.Background(), slog.Record{})
	}

	if counter.Total() != 10 {
		t.Errorf("expected 10, got %d", counter.Total())
	}

	// Reset
	resetValue := counter.Reset()
	if resetValue != 10 {
		t.Errorf("expected reset to return 10, got %d", resetValue)
	}

	if counter.Total() != 0 {
		t.Errorf("expected 0 after reset, got %d", counter.Total())
	}
}

func BenchmarkSamplingHandler_Disabled(b *testing.B) {
	baseHandler := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	handler := NewSamplingHandler(baseHandler, SamplingConfig{Enabled: false})
	logger := slog.New(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i)
	}
}

func BenchmarkSamplingHandler_Enabled(b *testing.B) {
	baseHandler := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Second,
		Threshold: 100,
		Rate:      0.1,
		ErrorRate: 1.0,
	})
	logger := slog.New(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i)
	}
}

func TestSamplingHandler_NeverSampleMessages(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:             true,
		Tick:                time.Minute,
		Threshold:           5,
		Rate:                0.0, // Drop all after threshold
		ErrorRate:           1.0,
		NeverSampleMessages: []string{"audit:", "security:"},
	})

	logger := slog.New(handler)

	// Log 20 regular messages - only 5 should be logged
	for i := 0; i < 20; i++ {
		logger.Info("regular message")
	}

	// Log 20 audit messages - ALL should be logged (never sampled)
	for i := 0; i < 20; i++ {
		logger.Info("audit: user login")
	}

	// Log 20 security messages - ALL should be logged (never sampled)
	for i := 0; i < 20; i++ {
		logger.Info("security: access denied")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 5 (regular threshold) + 20 (audit) + 20 (security) = 45
	if len(lines) != 45 {
		t.Errorf("expected 45 logs (5 regular + 40 never-sampled), got %d", len(lines))
	}
}

func TestSamplingHandler_MaxCounterSize(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:        true,
		Tick:           time.Minute,
		Threshold:      1,
		Rate:           0.0,
		ErrorRate:      1.0,
		MaxCounterSize: 10, // Very small limit for testing
	})

	logger := slog.New(handler)

	// Log 20 unique messages
	// First 10 create counters (1 each logged due to threshold)
	// Next 10 exceed counter limit, so they're all logged (no counting)
	for i := 0; i < 20; i++ {
		logger.Info("unique message " + string(rune('A'+i)))
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Expected: 10 (threshold 1 each) + 10 (all logged due to counter limit) = 20
	if len(lines) != 20 {
		t.Errorf("expected 20 logs with MaxCounterSize limit, got %d", len(lines))
	}
}

func TestSamplingHandler_OnDroppedPanicProtection(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:   true,
		Tick:      time.Minute,
		Threshold: 1,
		Rate:      0.0,
		ErrorRate: 1.0,
		OnDropped: func(ctx context.Context, record slog.Record) {
			panic("intentional panic in OnDropped")
		},
	})

	logger := slog.New(handler)

	// Should not panic even though OnDropped panics
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("OnDropped panic was not caught: %v", r)
		}
	}()

	// Log multiple messages - second one will trigger OnDropped which panics
	for i := 0; i < 10; i++ {
		logger.Info("test message")
	}

	// Verify only 1 log was written (threshold)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 log, got %d", len(lines))
	}
}

func TestSamplingHandler_DefaultValues(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	// Create with zero values - should apply defaults
	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled: true,
		// All other values are zero
	})

	// Cast to access internal state
	sh := handler.(*samplingHandler)

	if sh.config.Tick != DefaultSamplingTick {
		t.Errorf("expected default Tick %v, got %v", DefaultSamplingTick, sh.config.Tick)
	}

	if sh.config.Threshold != DefaultSamplingThreshold {
		t.Errorf("expected default Threshold %d, got %d", DefaultSamplingThreshold, sh.config.Threshold)
	}

	if sh.config.MaxCounterSize != DefaultSamplingMaxCounterSize {
		t.Errorf("expected default MaxCounterSize %d, got %d", DefaultSamplingMaxCounterSize, sh.config.MaxCounterSize)
	}
}

func TestGetDroppedTotal(t *testing.T) {
	// Register metrics
	RegisterMetrics(nil)

	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	// Get initial count before this test
	initialCount := GetDroppedTotal("info")

	// Use EnableMetrics only (not OnDropped with MetricsOnDropped, that would double-count)
	handler := NewSamplingHandler(baseHandler, SamplingConfig{
		Enabled:       true,
		Tick:          time.Minute,
		Threshold:     1,
		Rate:          0.0, // Drop all after threshold
		ErrorRate:     1.0,
		EnableMetrics: true,
		// Note: Don't use OnDropped: MetricsOnDropped() - EnableMetrics already tracks metrics
	})

	logger := slog.New(handler)

	// Log multiple messages - first one is logged, rest are dropped
	for i := 0; i < 10; i++ {
		logger.Info("test message for dropped counter v2")
	}

	// Check dropped count increased
	finalCount := GetDroppedTotal("info")
	dropped := finalCount - initialCount

	// Expected: 9 dropped (10 total - 1 threshold)
	if dropped != 9 {
		t.Errorf("expected 9 dropped logs, got %v (initial=%v, final=%v)", dropped, initialCount, finalCount)
	}
}
