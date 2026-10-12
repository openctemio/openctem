package logger

import (
	"context"
	"log/slog"
	"regexp"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// logRecordsTotal counts WARN and ERROR records by component, before
// sampling, so a burst of errors is visible to alerting even when sampling
// drops most of the lines. The operator's "error log burst" alert reads it
// (docs/operations/monitoring.md).
var logRecordsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "openctem_log_records_total",
		Help: "WARN and ERROR log records written, by level and component (the logger's component, controller, worker or service attribute)",
	},
	[]string{"level", "component"},
)

// componentKeys are the logger attributes that name a component, set by code
// with a constant (log.With("controller", "cert-monitor")).
var componentKeys = map[string]bool{"component": true, "controller": true, "worker": true, "service": true}

// componentRe bounds a component label to what code constants look like.
var componentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,47}$`)

// maxComponents caps the number of distinct component labels: a component
// attribute set from a runtime value must not grow the series without bound.
const maxComponents = 200

const (
	componentNone  = "none"
	componentOther = "other"
)

var (
	componentsMu   sync.Mutex
	componentsSeen = map[string]bool{}
)

// componentLabel maps a component attribute value to its label: the value
// when it looks like a code constant and the cap is not reached, else
// "other".
func componentLabel(v string) string {
	if !componentRe.MatchString(v) {
		return componentOther
	}
	componentsMu.Lock()
	defer componentsMu.Unlock()
	if componentsSeen[v] {
		return v
	}
	if len(componentsSeen) >= maxComponents {
		return componentOther
	}
	componentsSeen[v] = true
	return v
}

// countingHandler counts WARN and ERROR records, then hands every record to
// the next handler unchanged.
type countingHandler struct {
	next      slog.Handler
	component string
}

func newCountingHandler(next slog.Handler) slog.Handler {
	return &countingHandler{next: next, component: componentNone}
}

func (h *countingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *countingHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		logRecordsTotal.WithLabelValues(levelToString(r.Level), h.component).Inc()
	}
	return h.next.Handle(ctx, r)
}

func (h *countingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	component := h.component
	for _, a := range attrs {
		if componentKeys[a.Key] {
			component = componentLabel(a.Value.String())
		}
	}
	return &countingHandler{next: h.next.WithAttrs(attrs), component: component}
}

func (h *countingHandler) WithGroup(name string) slog.Handler {
	return &countingHandler{next: h.next.WithGroup(name), component: h.component}
}
