package middleware

import (
	"math"
	"net/http"
	"strconv"
	"time"
)

// setRateLimitHeaders writes the rate-limit state of the current window in
// both header families:
//
//   - RateLimit-Limit, RateLimit-Remaining and RateLimit-Reset, the IETF draft
//     field names; Reset is the number of seconds until the window resets;
//   - the older X-RateLimit-* names the API has always sent; X-RateLimit-Reset
//     is a Unix timestamp. They stay for one deprecation window.
func setRateLimitHeaders(w http.ResponseWriter, limit, remaining int, resetAt time.Time) {
	h := w.Header()
	h.Set("X-RateLimit-Limit", strconv.Itoa(limit))
	h.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	h.Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
	h.Set("RateLimit-Limit", strconv.Itoa(limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(secondsUntil(resetAt)))
}

// setRateLimitRemaining overrides the remaining count in both families, for a
// limiter that reports the full allowance first and refuses afterwards.
func setRateLimitRemaining(w http.ResponseWriter, remaining int) {
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
}

// secondsUntil rounds up to whole seconds and never goes below zero.
func secondsUntil(t time.Time) int {
	d := time.Until(t)
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
