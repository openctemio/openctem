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

func TestAsyncHandler_Disabled(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	// Async disabled - should pass through directly
	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled: false,
	})

	logger := slog.New(handler)
	logger.Info("test message")

	// Should be written immediately
	if !strings.Contains(buf.String(), "test message") {
		t.Error("expected log to be written immediately when async disabled")
	}
}

func TestAsyncHandler_Basic(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	defer handler.Close()

	logger := slog.New(handler)

	// Write some logs
	for i := 0; i < 10; i++ {
		logger.Info("test message", "index", i)
	}

	// Wait for async flush
	time.Sleep(50 * time.Millisecond)

	// Count log lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 logs, got %d", len(lines))
	}
}

func TestAsyncHandler_Close(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: time.Hour, // Long interval, rely on Close()
	})

	logger := slog.New(handler)

	// Write logs
	for i := 0; i < 5; i++ {
		logger.Info("test message", "index", i)
	}

	// Close should flush all
	handler.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 logs after Close, got %d", len(lines))
	}
}

func TestAsyncHandler_CloseMultipleTimes(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: time.Hour,
	})

	logger := slog.New(handler)
	logger.Info("test message")

	// Close multiple times should not panic
	handler.Close()
	handler.Close()
	handler.Close()
}

func TestAsyncHandler_Flush(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: time.Hour, // Long interval
	})
	defer handler.Close()

	logger := slog.New(handler)

	// Write logs
	logger.Info("message 1")
	logger.Info("message 2")

	// Give time for logs to enter buffer
	time.Sleep(10 * time.Millisecond)

	// Flush should write all buffered logs
	handler.Flush()

	if !strings.Contains(buf.String(), "message 1") {
		t.Error("expected message 1 after Flush")
	}
	if !strings.Contains(buf.String(), "message 2") {
		t.Error("expected message 2 after Flush")
	}
}

func TestAsyncHandler_DropOnFull(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	var dropCount atomic.Int32

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    5, // Small buffer
		FlushInterval: time.Hour,
		DropOnFull:    true,
		OnDrop: func(count int) {
			dropCount.Add(int32(count))
		},
	})
	defer handler.Close()

	logger := slog.New(handler)

	// Rapidly write more than buffer size
	for i := 0; i < 100; i++ {
		logger.Info("test message", "index", i)
	}

	// Some should have been dropped
	if dropCount.Load() == 0 {
		t.Error("expected some logs to be dropped when buffer full")
	}
}

func TestAsyncHandler_BlockOnFull(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    10,
		FlushInterval: 10 * time.Millisecond,
		DropOnFull:    false, // Block instead of drop
	})
	defer handler.Close()

	logger := slog.New(handler)

	// Write logs - should not lose any
	for i := 0; i < 50; i++ {
		logger.Info("test message", "index", i)
	}

	// Wait for all to be processed
	time.Sleep(100 * time.Millisecond)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 logs with blocking, got %d", len(lines))
	}
}

func TestAsyncHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	defer handler.Close()

	// Create logger with attrs
	derivedHandler := handler.WithAttrs([]slog.Attr{
		slog.String("service", "test"),
	})
	logger := slog.New(derivedHandler)

	logger.Info("test message")

	time.Sleep(50 * time.Millisecond)

	// Check that the log was written (attrs are embedded in JSON)
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("expected message to be logged")
	}
	// JSONHandler embeds attrs in the output
	if !strings.Contains(output, "service") || !strings.Contains(output, "test") {
		t.Errorf("expected WithAttrs to be preserved, got: %s", output)
	}
}

func TestAsyncHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	defer handler.Close()

	// Create logger with group
	derivedHandler := handler.WithGroup("mygroup")
	logger := slog.New(derivedHandler)
	logger.Info("test message", "key", "value")

	time.Sleep(50 * time.Millisecond)

	// JSONHandler nests attributes under the group name
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("expected message to be logged")
	}
	// Group creates nested JSON: {"mygroup":{"key":"value"}}
	if !strings.Contains(output, "mygroup") {
		t.Errorf("expected WithGroup to be preserved, got: %s", output)
	}
}

func TestAsyncHandler_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	baseHandler := slog.NewJSONHandler(&safeWriter{Writer: &buf, mu: &mu}, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    1000,
		FlushInterval: 10 * time.Millisecond,
	})
	defer handler.Close()

	logger := slog.New(handler)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				logger.Info("concurrent message", "goroutine", id, "index", j)
			}
		}(i)
	}

	wg.Wait()
	handler.Close() // Ensure all flushed

	mu.Lock()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	mu.Unlock()

	if len(lines) != 1000 {
		t.Errorf("expected 1000 concurrent logs, got %d", len(lines))
	}
}

// safeWriter is a thread-safe writer for testing
type safeWriter struct {
	Writer *bytes.Buffer
	mu     *sync.Mutex
}

func (w *safeWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Writer.Write(p)
}

func TestAsyncHandler_RecordCloning(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	defer handler.Close()

	// Test that records are properly cloned (no data races)
	logger := slog.New(handler)

	// This pattern could cause issues if records aren't cloned
	for i := 0; i < 100; i++ {
		attrs := []any{"index", i, "data", strings.Repeat("x", 100)}
		logger.Info("test message", attrs...)
	}

	handler.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 100 {
		t.Errorf("expected 100 logs, got %d", len(lines))
	}
}

func TestAsyncHandler_WithAttrsAndClose(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: time.Hour,
	})

	// Create derived handler with attrs
	derived := handler.WithAttrs([]slog.Attr{slog.String("key", "value")})
	logger := slog.New(derived)
	logger.Info("test")

	// Close derived handler (should work via shared once/wg)
	if closer, ok := derived.(*asyncHandler); ok {
		closer.Close()
	}

	// Original handler close should be no-op
	handler.Close()

	if !strings.Contains(buf.String(), "test") {
		t.Error("expected log to be flushed on Close")
	}
}

func TestAsyncWriter_Basic(t *testing.T) {
	var buf bytes.Buffer

	writer := NewAsyncWriter(&buf, AsyncConfig{
		Enabled:       true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	defer writer.Close()

	writer.Write([]byte("hello\n"))
	writer.Write([]byte("world\n"))

	time.Sleep(50 * time.Millisecond)

	if !strings.Contains(buf.String(), "hello") {
		t.Error("expected hello to be written")
	}
	if !strings.Contains(buf.String(), "world") {
		t.Error("expected world to be written")
	}
}

func TestAsyncWriter_Disabled(t *testing.T) {
	var buf bytes.Buffer

	writer := NewAsyncWriter(&buf, AsyncConfig{
		Enabled: false,
	})

	writer.Write([]byte("hello"))

	// Should be written immediately
	if buf.String() != "hello" {
		t.Error("expected immediate write when disabled")
	}
}

func TestAsyncHandler_Enabled(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:    true,
		BufferSize: 100,
	})
	defer handler.Close()

	// Test Enabled method
	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected handler to be enabled for Info level")
	}
}

func BenchmarkAsyncHandler_Enabled(b *testing.B) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled:       true,
		BufferSize:    10000,
		FlushInterval: 100 * time.Millisecond,
	})
	defer handler.Close()

	logger := slog.New(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "index", i)
	}
}

func BenchmarkAsyncHandler_Disabled(b *testing.B) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)

	handler := NewAsyncHandler(baseHandler, AsyncConfig{
		Enabled: false,
	})

	logger := slog.New(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "index", i)
	}
}
