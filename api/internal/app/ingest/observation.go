package ingest

// When a file saw a finding, and what a passed compliance check means
// (docs/architecture/finding-import.md, "What a Nessus import closes").
//
// A scan file is uploaded after the scan, sometimes days after, and files
// arrive out of order. Each finding of a file carries when the scan saw it
// (last_seen_at: a Nessus host's scan end). That time, not the upload's, is
// the sighting: a finding's last seen time only moves forward (the newer of
// the stored and the file's time), and a file reopens a closed finding only
// when it saw the finding after the finding was closed. Importing the same
// file twice changes nothing the first import did not.
//
// A compliance check that passed is not a finding: it is neither stored nor a
// sighting of the failed result of the same check (same host, framework,
// control and resource). It is recorded (CompliancePassed) so an upload can
// resolve that open failure; a warning, an error or a not-applicable result
// never resolves it. Every compliance result is also the state of its control
// (compliance_checks.go).

import (
	"context"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// CompliancePass is a passed compliance result of a report: the stored
// fingerprint of its check on its asset, and when the check ran.
type CompliancePass struct {
	Fingerprint string
	AssetID     shared.ID
	ObservedAt  time.Time
}

// findingObservedAt is when the producer saw f: its last_seen_at when that
// is a plausible time not after now, else fallback.
func findingObservedAt(f *ctis.Finding, fallback, now time.Time) time.Time {
	if f == nil || f.LastSeenAt == nil {
		return fallback
	}
	t := f.LastSeenAt.UTC()
	if t.Before(earliestLastSeen) || t.After(now) {
		return fallback
	}
	return t
}

// groupByObservedAt splits fingerprints by the time each was observed, in
// the order the times first appear (a reopen compares that time with when
// the finding was closed).
func groupByObservedAt(fingerprints []string, at map[string]time.Time, fallback time.Time) ([]time.Time, map[time.Time][]string) {
	order := []time.Time{}
	groups := map[time.Time][]string{}
	for _, fp := range fingerprints {
		t, ok := at[fp]
		if !ok {
			t = fallback
		}
		if _, seen := groups[t]; !seen {
			order = append(order, t)
		}
		groups[t] = append(groups[t], fp)
	}
	return order, groups
}

// validFindingTimes maps each fingerprint of a file's findings to when the
// file saw it (fileObserved: an upload); nil otherwise, so every finding
// takes the report's time.
func validFindingTimes[T any](items []T, of func(T) (string, *ctis.Finding), fileObserved bool) map[string]time.Time {
	if !fileObserved {
		return nil
	}
	now := time.Now().UTC()
	out := make(map[string]time.Time, len(items))
	for _, it := range items {
		fp, f := of(it)
		if f == nil || f.LastSeenAt == nil {
			continue
		}
		if t := findingObservedAt(f, time.Time{}, now); !t.IsZero() {
			out[fp] = t
		}
	}
	return out
}

// autoReopen reopens the closed findings among fingerprints, each compared
// with the time it was observed (at, else the report's): a file reopens a
// finding only when it saw it after the finding was closed.
func (p *FindingProcessor) autoReopen(ctx context.Context, tenantID shared.ID, report *ctis.Report, fingerprints []string,
	at map[string]time.Time) (map[string]vulnerability.ReopenedFinding, error) {
	fallback := reportObservedAt(report, time.Now())
	if len(at) == 0 {
		return p.repo.AutoReopenByFingerprintsBatch(ctx, tenantID, fingerprints, fallback)
	}
	order, groups := groupByObservedAt(fingerprints, at, fallback)
	out := map[string]vulnerability.ReopenedFinding{}
	for _, t := range order {
		m, err := p.repo.AutoReopenByFingerprintsBatch(ctx, tenantID, groups[t], t)
		if err != nil {
			return out, err
		}
		for k, v := range m {
			out[k] = v
		}
	}
	return out, nil
}
