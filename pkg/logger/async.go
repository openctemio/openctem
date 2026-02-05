package logger

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
)

// AsyncConfig configures async buffered logging.
type AsyncConfig struct {
	// Enabled turns async logging on/off (default: false)
	Enabled bool

	// BufferSize is the size of the log buffer (default: 4096)
	// Larger buffers reduce I/O frequency but use more memory
	BufferSize int

	// FlushInterval is how often to flush the buffer (default: 100ms)
	FlushInterval time.Duration

	// DropOnFull determines behavior when buffer is full
	// true = drop logs (never block), false = block until space available (default: false)
	DropOnFull bool

	// OnDrop is called when a log is dropped due to full buffer (optional)
	OnDrop func(count int)
}

// DefaultAsyncConfig returns sensible defaults for production.
func DefaultAsyncConfig() AsyncConfig {
	return AsyncConfig{
		Enabled:       false, // Disabled by default for safety
		BufferSize:    4096,
		FlushInterval: 100 * time.Millisecond,
		DropOnFull:    false,
		OnDrop:        nil,
	}
}

// asyncHandler wraps another handler with async buffered writes.
//
// NOTE: This handler is not yet integrated into the main logger factory.
// It is available for direct use when needed. Integration is planned for
// a future release after thorough testing.
type asyncHandler struct {
	handler slog.Handler
	config  AsyncConfig
	records chan asyncRecord
	wg      *sync.WaitGroup // pointer to allow sharing across WithAttrs/WithGroup
	done    chan struct{}
	once    *sync.Once // pointer to allow sharing across WithAttrs/WithGroup
}

type asyncRecord struct {
	ctx     context.Context
	record  slog.Record
	handler slog.Handler // The handler to use for this record
}

// NewAsyncHandler creates a handler that buffers logs and writes them asynchronously.
// This reduces I/O blocking in the hot path.
//
// IMPORTANT: Call Close() or Flush() before application shutdown to ensure
// all buffered logs are written.
//
// NOTE: This handler is not yet integrated into the main logger factory (New()).
// Use it directly when you need async logging:
//
//	baseHandler := slog.NewJSONHandler(os.Stdout, nil)
//	asyncHandler := logger.NewAsyncHandler(baseHandler, logger.AsyncConfig{Enabled: true})
//	defer asyncHandler.Close()
//	slog.SetDefault(slog.New(asyncHandler))
func NewAsyncHandler(h slog.Handler, cfg AsyncConfig) *asyncHandler {
	if !cfg.Enabled {
		return &asyncHandler{handler: h, config: cfg}
	}

	// Apply defaults
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}

	wg := &sync.WaitGroup{}
	once := &sync.Once{}

	ah := &asyncHandler{
		handler: h,
		config:  cfg,
		records: make(chan asyncRecord, cfg.BufferSize),
		done:    make(chan struct{}),
		wg:      wg,
		once:    once,
	}

	ah.wg.Add(1)
	go ah.worker()

	return ah
}

func (h *asyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *asyncHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.config.Enabled {
		return h.handler.Handle(ctx, r)
	}

	// Clone the record to avoid data races
	// slog.Record contains a slice that may be reused
	record := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		record.AddAttrs(a)
		return true
	})

	if h.config.DropOnFull {
		select {
		case h.records <- asyncRecord{ctx: ctx, record: record, handler: h.handler}:
		default:
			// Buffer full, drop the log
			if h.config.OnDrop != nil {
				h.config.OnDrop(1)
			}
		}
	} else {
		// Block until space available
		h.records <- asyncRecord{ctx: ctx, record: record, handler: h.handler}
	}

	return nil
}

func (h *asyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &asyncHandler{
		handler: h.handler.WithAttrs(attrs),
		config:  h.config,
		records: h.records, // Share the same channel
		done:    h.done,
		wg:      h.wg,   // Share WaitGroup for proper Close()
		once:    h.once, // Share Once for proper Close()
	}
}

func (h *asyncHandler) WithGroup(name string) slog.Handler {
	return &asyncHandler{
		handler: h.handler.WithGroup(name),
		config:  h.config,
		records: h.records, // Share the same channel
		done:    h.done,
		wg:      h.wg,   // Share WaitGroup for proper Close()
		once:    h.once, // Share Once for proper Close()
	}
}

func (h *asyncHandler) worker() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			// Drain remaining records
			h.drain()
			return

		case rec := <-h.records:
			// Use the handler stored in the record (supports WithAttrs/WithGroup)
			_ = rec.handler.Handle(rec.ctx, rec.record)

		case <-ticker.C:
			// Periodic flush - drain all available records
			h.drainNonBlocking()
		}
	}
}

func (h *asyncHandler) drain() {
	for {
		select {
		case rec := <-h.records:
			_ = rec.handler.Handle(rec.ctx, rec.record)
		default:
			return
		}
	}
}

func (h *asyncHandler) drainNonBlocking() {
	for {
		select {
		case rec := <-h.records:
			_ = rec.handler.Handle(rec.ctx, rec.record)
		default:
			return
		}
	}
}

// Flush blocks until all currently buffered logs are written.
// Note: This only flushes logs that are already in the buffer at the time
// of the call. New logs may be added while flushing.
func (h *asyncHandler) Flush() {
	if !h.config.Enabled {
		return
	}

	// Use a marker to ensure we've processed all records up to this point.
	// We do this by waiting for the channel to be empty, then checking again.
	for {
		select {
		case rec := <-h.records:
			_ = rec.handler.Handle(rec.ctx, rec.record)
		default:
			// Channel is empty, we're done
			return
		}
	}
}

// Close stops the async worker and flushes remaining logs.
// Always call this before application shutdown.
// Safe to call multiple times (subsequent calls are no-ops).
func (h *asyncHandler) Close() error {
	if !h.config.Enabled || h.once == nil {
		return nil
	}

	h.once.Do(func() {
		close(h.done)
		h.wg.Wait()
	})

	return nil
}

// AsyncWriter wraps an io.Writer with async buffered writes.
// This is an alternative to AsyncHandler when you want to make
// any writer async (e.g., file writer).
type AsyncWriter struct {
	writer io.Writer
	buffer chan []byte
	done   chan struct{}
	wg     sync.WaitGroup
	config AsyncConfig
}

// NewAsyncWriter creates an async buffered writer.
func NewAsyncWriter(w io.Writer, cfg AsyncConfig) *AsyncWriter {
	if !cfg.Enabled {
		return &AsyncWriter{writer: w, config: cfg}
	}

	aw := &AsyncWriter{
		writer: w,
		buffer: make(chan []byte, cfg.BufferSize),
		done:   make(chan struct{}),
		config: cfg,
	}

	aw.wg.Add(1)
	go aw.worker()

	return aw
}

func (w *AsyncWriter) Write(p []byte) (n int, err error) {
	if !w.config.Enabled {
		return w.writer.Write(p)
	}

	// Copy the data to avoid data races
	data := make([]byte, len(p))
	copy(data, p)

	if w.config.DropOnFull {
		select {
		case w.buffer <- data:
		default:
			if w.config.OnDrop != nil {
				w.config.OnDrop(1)
			}
		}
	} else {
		w.buffer <- data
	}

	return len(p), nil
}

func (w *AsyncWriter) worker() {
	defer w.wg.Done()

	for {
		select {
		case <-w.done:
			w.drain()
			return
		case data := <-w.buffer:
			_, _ = w.writer.Write(data)
		}
	}
}

func (w *AsyncWriter) drain() {
	for {
		select {
		case data := <-w.buffer:
			_, _ = w.writer.Write(data)
		default:
			return
		}
	}
}

// Close stops the async writer and flushes remaining data.
func (w *AsyncWriter) Close() error {
	if !w.config.Enabled {
		return nil
	}

	close(w.done)
	w.wg.Wait()
	return nil
}
