package proxypool

import (
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Health states of an endpoint.
const (
	// StateHealthy endpoints carry their full weight.
	StateHealthy = "healthy"
	// StateProbation endpoints are new or recovering: they get a small
	// share of the traffic until they prove themselves.
	StateProbation = "probation"
	// StateQuarantined endpoints get no traffic until their back-off ends;
	// they then come back in probation (the re-probe is the next job's
	// real traffic at a small weight).
	StateQuarantined = "quarantined"
)

// Scoring constants: measured defaults, not settings.
const (
	healthyScore       = 0.6
	quarantineScore    = 0.3
	quarantineFailures = 3  // consecutive failed reports
	promoteAfterOK     = 20 // clean connections in probation
	// successHalfLife is how many connections halve the weight of the past
	// in the success average.
	successHalfLife  = 20.0
	quarantineBase   = 5 * time.Minute
	quarantineMax    = 2 * time.Hour
	probationShare   = 0.05
	minWeight        = 0.01
	maxLastErrorRune = 200
	// newScore is the score of an endpoint nobody has reported on.
	newScore = 0.5
)

// Health is what the platform knows about an endpoint from sensor reports.
type Health struct {
	State               string
	Score               float64
	SuccessEWMA         float64
	ConsecutiveFailures int
	ProbationOK         int
	QuarantineCount     int
	OKTotal             int64
	FailTotal           int64
	HandshakeMsP95      *int
	LastError           string
	LastOKAt            *time.Time
	LastFailureAt       *time.Time
	QuarantinedUntil    *time.Time
	StateChangedAt      time.Time
}

// NewHealth is the health of a new endpoint: probation, neutral score.
func NewHealth(now time.Time) Health {
	return Health{State: StateProbation, Score: newScore, SuccessEWMA: 1, StateChangedAt: now}
}

// Reset puts an endpoint back to a new endpoint's health, keeping its
// totals (an administrator fixed it, or its credentials changed).
func (h *Health) Reset(now time.Time) {
	ok, fail := h.OKTotal, h.FailTotal
	*h = NewHealth(now)
	h.OKTotal, h.FailTotal = ok, fail
}

// Signal is one sensor's report on one endpoint for one job.
type Signal struct {
	OK                int
	ProxyDown         int
	ProxyAuth         int
	TargetUnreachable int
	TargetRefused     int
	HandshakeMsP50    int
	HandshakeMsP95    int
	LastError         string
}

// Eligible reports whether the endpoint may carry traffic now: healthy, in
// probation, or quarantined with its back-off over.
func (h *Health) Eligible(now time.Time) bool {
	return h.State != StateQuarantined || (h.QuarantinedUntil != nil && !now.Before(*h.QuarantinedUntil))
}

// Weight is the endpoint's selection weight for a job (> 0), or 0 when it is
// not eligible: score² for a healthy endpoint (good endpoints are favored
// without one taking everything), a small share for one in probation.
func (h *Health) Weight(now time.Time) float64 {
	if !h.Eligible(now) {
		return 0
	}
	if h.State == StateHealthy {
		return math.Max(h.Score*h.Score, minWeight)
	}
	s := math.Max(h.Score, newScore)
	return math.Max(probationShare*s*s, minWeight*probationShare)
}

// Apply folds one report into the health and moves the state. It returns
// true when the state changed.
func (h *Health) Apply(sig Signal, now time.Time) bool {
	before := h.State
	sig = clampSignal(sig)
	attempts := sig.OK + sig.ProxyDown
	if attempts > 0 {
		alpha := 1 - math.Pow(0.5, float64(attempts)/successHalfLife)
		h.SuccessEWMA = h.SuccessEWMA*(1-alpha) + float64(sig.OK)/float64(attempts)*alpha
	}
	failed := sig.ProxyDown + sig.ProxyAuth
	switch {
	case sig.OK > 0:
		h.ConsecutiveFailures = 0
	case failed > 0:
		h.ConsecutiveFailures++
	}
	if sig.HandshakeMsP95 > 0 {
		p := sig.HandshakeMsP95
		h.HandshakeMsP95 = &p
	}
	h.OKTotal += int64(sig.OK)
	h.FailTotal += int64(failed)
	if sig.OK > 0 {
		t := now
		h.LastOKAt = &t
	}
	if failed > 0 {
		t := now
		h.LastFailureAt = &t
		h.LastError = SanitizeError(sig.LastError)
	}
	if attempts > 0 || failed > 0 {
		// Target errors say nothing about the proxy.
		h.Score = h.score()
	}

	expired := h.State == StateQuarantined && h.Eligible(now)
	switch {
	case sig.ProxyAuth > 0 && sig.OK == 0:
		// Wrong credentials: no traffic until the back-off ends or an
		// administrator changes them.
		h.quarantine(now)
	case h.State == StateQuarantined && !expired:
		// A late report of a job that started before the quarantine.
		if sig.OK > 0 && failed == 0 {
			h.toProbation(now, sig.OK)
		}
	case expired:
		// The re-probe: the first report after the back-off decides.
		if sig.OK > 0 {
			h.toProbation(now, sig.OK)
		} else if failed > 0 {
			h.quarantine(now)
		}
	case h.Score < quarantineScore || h.ConsecutiveFailures >= quarantineFailures:
		h.quarantine(now)
	case h.State == StateProbation:
		h.ProbationOK += sig.OK
		if h.ProbationOK >= promoteAfterOK && h.Score >= healthyScore {
			h.State, h.StateChangedAt = StateHealthy, now
			h.QuarantineCount, h.QuarantinedUntil = 0, nil
		}
	}
	return h.State != before
}

func (h *Health) score() float64 {
	lat := 1.0
	if h.HandshakeMsP95 != nil {
		lat = clamp01(1 - float64(*h.HandshakeMsP95-200)/2000)
	}
	penalty := 0.15 * float64(min(h.ConsecutiveFailures, 4))
	return clamp01(0.8*h.SuccessEWMA + 0.2*lat - penalty)
}

func (h *Health) quarantine(now time.Time) {
	h.QuarantineCount++
	backoff := quarantineBase << min(h.QuarantineCount-1, 10)
	if backoff > quarantineMax || backoff <= 0 {
		backoff = quarantineMax
	}
	until := now.Add(backoff)
	h.State, h.QuarantinedUntil, h.ProbationOK, h.StateChangedAt = StateQuarantined, &until, 0, now
}

func (h *Health) toProbation(now time.Time, ok int) {
	h.State, h.QuarantinedUntil, h.ProbationOK, h.StateChangedAt = StateProbation, nil, ok, now
	h.ConsecutiveFailures = 0
	h.Score = h.score()
}

func clampSignal(s Signal) Signal {
	c := func(v int) int { return min(max(v, 0), 1_000_000) }
	s.OK, s.ProxyDown, s.ProxyAuth = c(s.OK), c(s.ProxyDown), c(s.ProxyAuth)
	s.TargetUnreachable, s.TargetRefused = c(s.TargetUnreachable), c(s.TargetRefused)
	s.HandshakeMsP50, s.HandshakeMsP95 = min(max(s.HandshakeMsP50, 0), 600_000), min(max(s.HandshakeMsP95, 0), 600_000)
	return s
}

func clamp01(v float64) float64 { return math.Min(math.Max(v, 0), 1) }

// SanitizeError makes a sensor's error text safe to store and show: one
// line, printable, at most 200 characters, and no URL user information
// (a sensor never sends credentials, but the platform does not rely on it).
func SanitizeError(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = stripUserinfo(strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > maxLastErrorRune {
		s = string([]rune(s)[:maxLastErrorRune])
	}
	return s
}

// stripUserinfo removes "user:pass@" after every "://".
func stripUserinfo(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "://")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i+3])
		s = s[i+3:]
		end := strings.IndexAny(s, " /\"'")
		if end < 0 {
			end = len(s)
		}
		if at := strings.LastIndexByte(s[:end], '@'); at >= 0 {
			s = s[at+1:]
		}
	}
}
