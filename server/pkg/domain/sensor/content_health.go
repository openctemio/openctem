package sensor

import (
	"fmt"
	"strings"
	"time"
)

// Health reasons for scanner content (RFC-031).
const (
	// ReasonContentStale: managed content is older than the tenant's limit.
	ReasonContentStale HealthReasonCode = "content_stale"
	// ReasonContentRefreshFailed: the last refresh failed; the sensor still
	// scans with the version it has, which is not (yet) stale.
	ReasonContentRefreshFailed HealthReasonCode = "content_refresh_failed"
)

// contentReasons lists the content problems of a sensor under the policy
// (nil policy: the platform default). Unmanaged content is never flagged: the
// sensor does not control it.
func (a *Sensor) contentReasons(now time.Time, policy *ContentPolicy) []HealthReason {
	if len(a.ReportedContent()) == 0 {
		return nil
	}
	p := DefaultContentPolicy()
	if policy != nil {
		p = policy.WithDefaults(DefaultContentPolicy())
	}
	var reasons []HealthReason
	for _, v := range a.ContentViews(now, p) {
		if !v.Managed {
			continue
		}
		label, plural := contentLabel(v.Name)
		verb := "is"
		if plural {
			verb = "are"
		}
		errText := strings.TrimRight(v.Error, ". ")
		switch {
		case v.Stale:
			msg := fmt.Sprintf("The %s %s missing (limit %s).", label, verb, humanDuration(time.Duration(v.MaxAgeHours)*time.Hour))
			if v.AgeSeconds != nil {
				msg = fmt.Sprintf("The %s %s %s old (limit %s).", label, verb,
					humanDuration(time.Duration(*v.AgeSeconds)*time.Second),
					humanDuration(time.Duration(v.MaxAgeHours)*time.Hour))
			}
			if v.Unconfirmed != nil {
				msg += fmt.Sprintf(" The sensor has not confirmed a newer version for %s.", humanDuration(*v.Unconfirmed))
			}
			if errText != "" {
				msg += " The last refresh failed: " + errText + "."
			} else {
				msg += " Refresh the sensor's content or check that it can reach its content source."
			}
			reasons = append(reasons, HealthReason{Code: ReasonContentStale, Severity: SeverityWarning, Message: msg})
		case errText != "":
			msg := fmt.Sprintf("Refreshing the %s failed: %s.", label, errText)
			if v.Version != "" {
				msg += " Scans use " + v.Version + "."
			}
			reasons = append(reasons, HealthReason{Code: ReasonContentRefreshFailed, Severity: SeverityWarning, Message: msg})
		}
	}
	return reasons
}
