package logger

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// SamplingConfig configures log sampling behavior.
// Sampling helps reduce log volume in high-traffic production environments.
type SamplingConfig struct {
	// Enabled turns sampling on/off (default: false for backward compatibility)
	Enabled bool

	// Tick is the sampling interval (default: 1 second)
	// Counters reset after each tick
	Tick time.Duration

	// Threshold is the number of identical logs allowed per tick before sampling kicks in
	// First N logs are always logged, then sampling applies (default: 100)
	Threshold uint64

	// Rate is the sampling rate after threshold is reached [0.0, 1.0]
	// 0.1 = log 10% of messages after threshold (default: 0.1)
	Rate float64

	// ErrorRate is the sampling rate for error/warn level logs [0.0, 1.0]
	// Errors are typically more important, so higher rate (default: 1.0 = 100%)
	ErrorRate float64

	// MaxCounterSize limits the number of unique message keys to track (default: 10000)
	// Prevents memory growth with many unique messages
	MaxCounterSize int

	// NeverSampleMessages are message prefixes that should never be sampled
	// Useful for security/audit logs that must always be logged
	// Example: []string{"audit:", "security:", "auth:"}
	NeverSampleMessages []string

	// OnDropped is called when a log is dropped (optional, for metrics)
	// Protected against panics - callback errors are silently ignored
	OnDropped func(ctx context.Context, record slog.Record)

	// EnableMetrics enables Prometheus metrics for dropped logs
	EnableMetrics bool
}

// Default values for sampling configuration
const (
	DefaultSamplingTick           = time.Second
	DefaultSamplingThreshold      = 100
	DefaultSamplingRate           = 0.1
	DefaultSamplingErrorRate      = 1.0
	DefaultSamplingMaxCounterSize = 10000
)

// DefaultSamplingConfig returns sensible defaults for production.
func DefaultSamplingConfig() SamplingConfig {
	return SamplingConfig{
		Enabled:             false, // Disabled by default for safety
		Tick:                DefaultSamplingTick,
		Threshold:           DefaultSamplingThreshold,
		Rate:                DefaultSamplingRate,
		ErrorRate:           DefaultSamplingErrorRate,
		MaxCounterSize:      DefaultSamplingMaxCounterSize,
		NeverSampleMessages: nil,
		OnDropped:           nil,
		EnableMetrics:       false,
	}
}

// samplingHandler wraps another handler with sampling logic.
type samplingHandler struct {
	handler     slog.Handler
	config      SamplingConfig
	counters    sync.Map // map[string]*counter
	counterSize atomic.Int64
	lastReset   atomic.Int64
	neverSample map[string]bool // Precomputed for O(1) lookup
}

type counter struct {
	count atomic.Uint64
}

// NewSamplingHandler creates a handler that samples logs based on config.
// It wraps the provided handler and applies threshold-based sampling.
//
// Algorithm:
//   - First `Threshold` logs with same level+message are logged as-is
//   - After threshold, logs are sampled at `Rate` (or `ErrorRate` for errors)
//   - Counters reset every `Tick` interval
//   - Messages matching NeverSampleMessages prefixes are always logged
func NewSamplingHandler(h slog.Handler, cfg SamplingConfig) slog.Handler {
	if !cfg.Enabled {
		return h // No sampling, return original handler
	}

	// Apply defaults for zero values
	if cfg.Tick == 0 {
		cfg.Tick = DefaultSamplingTick
	}
	if cfg.Threshold == 0 {
		cfg.Threshold = DefaultSamplingThreshold
	}
	if cfg.MaxCounterSize == 0 {
		cfg.MaxCounterSize = DefaultSamplingMaxCounterSize
	}

	// Build never-sample prefix map
	neverSample := make(map[string]bool, len(cfg.NeverSampleMessages))
	for _, prefix := range cfg.NeverSampleMessages {
		neverSample[prefix] = true
	}

	sh := &samplingHandler{
		handler:     h,
		config:      cfg,
		neverSample: neverSample,
	}
	sh.lastReset.Store(time.Now().UnixNano())

	return sh
}

func (h *samplingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *samplingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Track metrics if enabled
	if h.config.EnableMetrics {
		MetricsOnProcessed(r.Level)
	}

	// Check if message should never be sampled (security/audit logs)
	if h.shouldNeverSample(r.Message) {
		return h.handler.Handle(ctx, r)
	}

	// Reset counters periodically
	h.maybeResetCounters()

	// Generate key for grouping (level + message)
	key := h.recordKey(r)

	// Check counter size limit to prevent memory leak
	currentSize := h.counterSize.Load()
	if currentSize >= int64(h.config.MaxCounterSize) {
		// Too many unique messages, just log without counting
		return h.handler.Handle(ctx, r)
	}

	// Get or create counter
	val, loaded := h.counters.LoadOrStore(key, &counter{})
	if !loaded {
		h.counterSize.Add(1)
	}
	cnt := val.(*counter)
	count := cnt.count.Add(1)

	// Always log if under threshold
	if count <= h.config.Threshold {
		return h.handler.Handle(ctx, r)
	}

	// Determine sampling rate based on level
	rate := h.config.Rate
	if r.Level >= slog.LevelWarn {
		rate = h.config.ErrorRate
	}

	// Sample based on rate
	if h.shouldSample(count, rate) {
		return h.handler.Handle(ctx, r)
	}

	// Log dropped - call OnDropped with panic protection
	h.onDropped(ctx, r)

	return nil
}

// shouldNeverSample checks if message starts with any never-sample prefix
func (h *samplingHandler) shouldNeverSample(message string) bool {
	if len(h.neverSample) == 0 {
		return false
	}

	for prefix := range h.neverSample {
		if len(message) >= len(prefix) && message[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// onDropped safely calls the OnDropped callback with panic protection
func (h *samplingHandler) onDropped(ctx context.Context, r slog.Record) {
	// Track metrics if enabled
	if h.config.EnableMetrics {
		level := levelToString(r.Level)
		logsDroppedTotal.WithLabelValues(level).Inc()
	}

	if h.config.OnDropped == nil {
		return
	}

	// Panic protection - don't let callback crash the application
	defer func() {
		_ = recover()
	}()

	h.config.OnDropped(ctx, r)
}

func (h *samplingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &samplingHandler{
		handler:     h.handler.WithAttrs(attrs),
		config:      h.config,
		counters:    sync.Map{},
		neverSample: h.neverSample,
	}
}

func (h *samplingHandler) WithGroup(name string) slog.Handler {
	return &samplingHandler{
		handler:     h.handler.WithGroup(name),
		config:      h.config,
		counters:    sync.Map{},
		neverSample: h.neverSample,
	}
}

func (h *samplingHandler) recordKey(r slog.Record) string {
	// Group by level and message for deduplication
	return r.Level.String() + ":" + r.Message
}

func (h *samplingHandler) shouldSample(count uint64, rate float64) bool {
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}

	// Simple deterministic sampling based on count
	// This ensures consistent sampling across instances
	interval := uint64(1.0 / rate)
	return count%interval == 0
}

func (h *samplingHandler) maybeResetCounters() {
	now := time.Now().UnixNano()
	last := h.lastReset.Load()
	tick := h.config.Tick.Nanoseconds()

	if now-last >= tick {
		if h.lastReset.CompareAndSwap(last, now) {
			// Clear all counters
			h.counters.Range(func(key, _ any) bool {
				h.counters.Delete(key)
				return true
			})
			// Reset counter size
			h.counterSize.Store(0)

			// Update metrics if enabled
			if h.config.EnableMetrics {
				SetSamplingCounterSize(0)
			}
		}
	}
}

// DroppedLogsCounter is a simple counter for tracking dropped logs.
// Use this with SamplingConfig.OnDropped to track sampling metrics.
type DroppedLogsCounter struct {
	total atomic.Uint64
}

func NewDroppedLogsCounter() *DroppedLogsCounter {
	return &DroppedLogsCounter{}
}

func (c *DroppedLogsCounter) Increment(ctx context.Context, record slog.Record) {
	c.total.Add(1)
}

func (c *DroppedLogsCounter) Total() uint64 {
	return c.total.Load()
}

func (c *DroppedLogsCounter) Reset() uint64 {
	return c.total.Swap(0)
}
