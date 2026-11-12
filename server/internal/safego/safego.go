// Package safego runs background work so that a panic in it cannot stop the
// process. A goroutine that panics without a recover kills the whole API,
// HTTP included; a deterministic panic (a bad row, a nil map) then becomes a
// crash loop on every replica.
//
// Run recovers a panic in fn, logs it once with the task name and the stack,
// counts it in openctem_panics_recovered_total{where=<name>} and returns it
// as an error. Go does the same in a new goroutine.
//
// The log carries the panic value (sanitized and capped: it can quote data
// the task was handling) and the stack (function names, files and lines,
// argument words as hex: no string contents).
package safego

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/openctemio/openctem/server/internal/metrics"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// ErrPanic is wrapped by the error Run returns for a recovered panic.
var ErrPanic = errors.New("panic recovered")

// maxPanicValue caps the logged panic value.
const maxPanicValue = 512

// Run calls fn and returns nil, or an error wrapping ErrPanic when fn
// panicked. name must be a constant of the call site (it is a metric
// label), never a value from a request or a row. log may be nil.
func Run(log *logger.Logger, name string, fn func()) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = Recovered(log, name, v)
		}
	}()
	fn()
	return nil
}

// Go runs fn in a new goroutine under Run.
func Go(log *logger.Logger, name string, fn func()) {
	go func() { _ = Run(log, name, fn) }()
}

// Recovered logs and counts a panic value a caller's own recover() caught,
// and returns it as an error wrapping ErrPanic. Call it from the deferred
// function that called recover(), so the stack still shows the panic site.
func Recovered(log *logger.Logger, name string, v any) error {
	metrics.RecordPanic(name)
	value := fmt.Sprint(v)
	if len(value) > maxPanicValue {
		// Drop the bytes of a character the cap split.
		value = strings.ToValidUTF8(value[:maxPanicValue], "")
	}
	value = logger.SanitizeValue(value)
	if log != nil {
		log.Error("background task panicked; recovered, the process keeps running",
			"task", name, "panic", value, "stack", string(debug.Stack()))
	}
	return fmt.Errorf("%w in %s: %s", ErrPanic, name, value)
}
