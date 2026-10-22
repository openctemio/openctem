package widgets

import (
	"fmt"
	"sync"
	"time"
)

// Widget previews (the gallery and the config panel) compute from the facts
// in the caller's own scope and are never stored, so each one costs a read.
// They are limited per person: a burst large enough for one gallery page of
// previews, then one every PreviewEvery. Per API process, like the read
// limiter.
const (
	PreviewBurst = 24
	PreviewEvery = 2 * time.Second
)

// ErrPreviewRate is returned when a person previews faster than the limit (429).
type ErrPreviewRate struct{ RetryAfter time.Duration }

func (e *ErrPreviewRate) Error() string {
	return fmt.Sprintf("too many widget previews; try again in %d s", max(int(e.RetryAfter.Seconds()+0.999), 1))
}

// previewLimiter is a token bucket per person. Buckets that are full again
// are dropped, so the map holds only people who previewed recently.
type previewLimiter struct {
	mu      sync.Mutex
	burst   float64
	every   time.Duration
	buckets map[string]*previewBucket
	swept   time.Time
}

type previewBucket struct {
	tokens float64
	at     time.Time
}

func newPreviewLimiter(burst int, every time.Duration) *previewLimiter {
	return &previewLimiter{burst: float64(burst), every: every, buckets: map[string]*previewBucket{}}
}

// take uses one preview of key at now; it returns 0 when allowed and how
// long to wait otherwise.
func (l *previewLimiter) take(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	full := time.Duration(l.burst) * l.every
	if now.Sub(l.swept) > full {
		for k, b := range l.buckets {
			if now.Sub(b.at) >= full {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &previewBucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.at); el > 0 {
		b.tokens = min(l.burst, b.tokens+float64(el)/float64(l.every))
		b.at = now
	}
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) * float64(l.every))
	}
	b.tokens--
	return 0
}
