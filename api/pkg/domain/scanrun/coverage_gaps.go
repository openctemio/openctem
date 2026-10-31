package scanrun

// Hosts a sensor could not fully cover in a completed task (RFC-074,
// docs/rfcs/RFC-074-adaptive-sensor-control.md): the sensor's per-host rate
// controller gave a host up after its breaker tripped, the host kept
// pushing back at the lowest rate, or it blocked the scan. The task still
// completes; its result metadata lists the hosts (coverage_gaps) and how
// many (coverage_gaps_total), and the step and the run end partial, so a
// host with a gap is never read as "no findings".
//
// The list is sensor-supplied: it is parsed defensively, bounded, cleaned
// and only ever shown as text.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Coverage-gap reasons a sensor reports. An entry with any other reason is
// dropped.
const (
	GapReasonBreakerOpen = "breaker_open"
	GapReasonRateFloor   = "rate_floor"
	GapReasonBlocked     = "blocked"
	// GapReasonProxyUnavailable: the proxy the scan used failed, so the
	// host was not judged.
	GapReasonProxyUnavailable = "proxy_unavailable"
)

// Bounds of a task's coverage gaps.
const (
	// MaxTaskCoverageGaps is how many gaps a task lists.
	MaxTaskCoverageGaps = 20
	// MaxCoverageGapsTotal caps the count a sensor reports.
	MaxCoverageGapsTotal = 1_000_000
	maxGapHostRunes      = 256
	maxGapDetailRunes    = 256
	maxGapsInSummary     = 5
)

// ErrCodeCoverageGaps is the code of a step that completed with hosts its
// sensor could not fully cover (FailureCoverageGaps, class partial).
const ErrCodeCoverageGaps = FailureCoverageGaps

// GapReasons lists the coverage-gap reasons the platform accepts, in a
// stable order (the console has words for each; a test checks it).
var GapReasons = []string{GapReasonBreakerOpen, GapReasonRateFloor, GapReasonBlocked, GapReasonProxyUnavailable}

// CoverageGap is one host a sensor could not fully cover, and why.
type CoverageGap struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// ParseCoverageGaps reads a task result's coverage_gaps list and
// coverage_gaps_total. It keeps at most MaxTaskCoverageGaps entries, cleans
// every string to one bounded line and drops entries without a host or with
// an unknown reason. The total is at least the number listed and at most
// MaxCoverageGapsTotal. Malformed input yields what could be read.
func ParseCoverageGaps(list json.RawMessage, total int) ([]CoverageGap, int) {
	var raw []map[string]any
	if len(list) > 0 {
		_ = json.Unmarshal(list, &raw)
	}
	out := make([]CoverageGap, 0, min(len(raw), MaxTaskCoverageGaps))
	seen := 0
	for _, e := range raw {
		host, _ := e["host"].(string)
		host = safetext.SingleLine(host, maxGapHostRunes)
		reason, _ := e["reason"].(string)
		if host == "" || !knownGapReason(reason) {
			continue
		}
		seen++
		if len(out) >= MaxTaskCoverageGaps {
			continue
		}
		detail, _ := e["detail"].(string)
		out = append(out, CoverageGap{Host: host, Reason: reason, Detail: safetext.SingleLine(detail, maxGapDetailRunes)})
	}
	if len(out) == 0 {
		out = nil
	}
	total = max(total, seen)
	total = min(total, MaxCoverageGapsTotal)
	return out, total
}

func knownGapReason(r string) bool {
	switch r {
	case GapReasonBreakerOpen, GapReasonRateFloor, GapReasonBlocked, GapReasonProxyUnavailable:
		return true
	}
	return false
}

// CoverageGapSummary is the step message of a task that completed with
// coverage gaps: "Completed with 2 host(s) not fully covered:
// api.example.com (breaker_open), www.example.com (blocked)".
func CoverageGapSummary(list []CoverageGap, total int) string {
	if total <= 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Completed with %d host(s) not fully covered", total)
	for i, g := range list {
		if i == maxGapsInSummary {
			break
		}
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%s)", g.Host, g.Reason)
	}
	if n := total - min(len(list), maxGapsInSummary); n > 0 && len(list) > 0 {
		fmt.Fprintf(&b, ", and %d more", n)
	}
	return b.String()
}
