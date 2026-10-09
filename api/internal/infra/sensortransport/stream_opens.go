package sensortransport

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// errStreamOpenRate refuses a control stream opened too soon after the
// sensor's previous ones.
var errStreamOpenRate = errors.New("control stream opened too often; retry later")

// openLimiter is a token bucket per sensor on control-stream opens
// (research/84 RE-12). The concurrent bound (MaxStreamsPerSensor) alone
// lets a sensor open and close streams in a loop, each open costing an
// authentication and a doorbell query. Per replica, like the concurrent
// bound.
type openLimiter struct {
	every rate.Limit
	burst int

	mu       sync.Mutex
	bySensor map[string]*rate.Limiter
	pruneAt  int
}

const openLimiterPruneFloor = 1024

func newOpenLimiter(perMinute, burst int) *openLimiter {
	return &openLimiter{every: rate.Limit(float64(perMinute) / 60), burst: burst,
		bySensor: map[string]*rate.Limiter{}, pruneAt: openLimiterPruneFloor}
}

// allow takes one open from the sensor's bucket.
func (l *openLimiter) allow(sensorID string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	lim := l.bySensor[sensorID]
	if lim == nil {
		l.prune(now)
		lim = rate.NewLimiter(l.every, l.burst)
		l.bySensor[sensorID] = lim
	}
	return lim.AllowN(now, 1)
}

// prune drops full buckets (forgetting them changes nothing: a new bucket
// starts full) once the map has doubled since the last sweep. Caller holds
// mu.
func (l *openLimiter) prune(now time.Time) {
	if len(l.bySensor) < l.pruneAt {
		return
	}
	for id, lim := range l.bySensor {
		if lim.TokensAt(now) >= float64(l.burst) {
			delete(l.bySensor, id)
		}
	}
	l.pruneAt = max(openLimiterPruneFloor, 2*len(l.bySensor))
}
