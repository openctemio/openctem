// Package vulnevent is the platform-wide log of material vulnerability
// changes: a new CVE with affected ranges, ranges that widened, a severity
// that rose, a KEV addition, an EPSS crossing, a rejection. Only public
// facts are recorded; no tenant data. The emerging-threat alert planner
// reads the log to decide which organizations to tell.
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md.
package vulnevent

import (
	"context"
	"slices"
	"strings"
	"time"
)

// Kind is what changed.
type Kind string

// Event kinds.
const (
	KindPublished     Kind = "published"
	KindRangesAdded   Kind = "ranges_added"
	KindRangesWidened Kind = "ranges_widened"
	KindSeverityUp    Kind = "severity_up"
	KindKEVAdded      Kind = "kev_added"
	KindEPSSCrossed   Kind = "epss_crossed"
	KindRejected      Kind = "rejected"
)

// AllKinds lists every kind.
func AllKinds() []Kind {
	return []Kind{KindPublished, KindRangesAdded, KindRangesWidened, KindSeverityUp, KindKEVAdded, KindEPSSCrossed, KindRejected}
}

// IsValid reports whether k is a known kind.
func (k Kind) IsValid() bool { return slices.Contains(AllKinds(), k) }

// Event is one material change.
type Event struct {
	ID     int64
	VulnID string
	Kind   Kind
	// At is when the platform saw it.
	At time.Time
	// SourceAt is when the source says it happened (published, KEV
	// dateAdded); nil when unknown.
	SourceAt     *time.Time
	FeedSequence *int64
	// Detail is small and enumerated: {"from":"medium","to":"critical"}.
	Detail map[string]any
}

// RecentWindow is how old a CVE's publication may be for its first ranges
// to count as "published" rather than "ranges_added".
const RecentWindow = 30 * 24 * time.Hour

// EPSS bands crossed upward emit an event.
const (
	EPSSBandLow  = 0.1
	EPSSBandHigh = 0.5
)

// EPSSBand maps a score to its band: 0 below 0.1, 1 below 0.5, 2 above.
func EPSSBand(score float64) int {
	switch {
	case score >= EPSSBandHigh:
		return 2
	case score >= EPSSBandLow:
		return 1
	}
	return 0
}

// State is what the emitter knows of one CVE record.
type State struct {
	VulnID    string
	Status    string
	Severity  string
	CVSSScore *float64
	// ProductIDs are the distinct catalog products the CVE's ranges name,
	// sorted.
	ProductIDs []string
	RangeCount int
	Published  *time.Time
	// FeedSequence is the bundle that last wrote the record (0: unknown).
	FeedSequence int64
}

var severityRank = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func rank(sev string) int { return severityRank[strings.ToLower(sev)] }

// IsRejected reports whether a record status withdraws the CVE.
func IsRejected(status string) bool {
	s := strings.ToLower(status)
	return s == "rejected" || s == "withdrawn"
}

// Diff returns the material changes from prev (nil: never seen) to cur.
// Edits that cannot change who is affected or how urgent it is (description,
// references, a CVSS move inside its band, ranges that narrowed) are not
// material.
func Diff(prev *State, cur State, now time.Time) []Event {
	var out []Event
	ev := func(k Kind, sourceAt *time.Time, detail map[string]any) {
		e := Event{VulnID: cur.VulnID, Kind: k, At: now, SourceAt: sourceAt, Detail: detail}
		if cur.FeedSequence > 0 {
			seq := cur.FeedSequence
			e.FeedSequence = &seq
		}
		out = append(out, e)
	}
	if IsRejected(cur.Status) {
		if prev != nil && !IsRejected(prev.Status) {
			ev(KindRejected, nil, map[string]any{"status": cur.Status})
		}
		return out
	}
	hadProducts := prev != nil && len(prev.ProductIDs) > 0
	switch {
	case len(cur.ProductIDs) == 0:
		// Nothing can match a CVE without products.
	case !hadProducts:
		if cur.Published != nil && now.Sub(*cur.Published) <= RecentWindow {
			ev(KindPublished, cur.Published, map[string]any{"products": len(cur.ProductIDs)})
		} else {
			ev(KindRangesAdded, nil, map[string]any{"products": len(cur.ProductIDs)})
		}
	default:
		added := newProducts(prev.ProductIDs, cur.ProductIDs)
		if added > 0 || cur.RangeCount > prev.RangeCount {
			ev(KindRangesWidened, nil, map[string]any{"products_added": added,
				"ranges_from": prev.RangeCount, "ranges_to": cur.RangeCount})
		}
	}
	if prev != nil && len(cur.ProductIDs) > 0 {
		up := prev.Severity != "" && rank(cur.Severity) > rank(prev.Severity)
		crossed9 := cur.CVSSScore != nil && *cur.CVSSScore >= 9.0 && (prev.CVSSScore == nil || *prev.CVSSScore < 9.0)
		if up || (crossed9 && rank(cur.Severity) == rank(prev.Severity)) {
			d := map[string]any{"from": strings.ToLower(prev.Severity), "to": strings.ToLower(cur.Severity)}
			if cur.CVSSScore != nil {
				d["cvss"] = *cur.CVSSScore
			}
			ev(KindSeverityUp, nil, d)
		}
	}
	return out
}

// newProducts counts the products of cur not in prev (both sorted).
func newProducts(prev, cur []string) int {
	n := 0
	for _, p := range cur {
		if _, found := slices.BinarySearch(prev, p); !found {
			n++
		}
	}
	return n
}

// Store persists the log and the emitter's state.
type Store interface {
	// BaselineCorpus records the state of every CVE record without
	// emitting anything (first run) and sets the corpus cursor to the
	// newest record.
	BaselineCorpus(ctx context.Context) (int, error)
	// CorpusCursor returns the corpus cursor; ok is false before the first
	// run.
	CorpusCursor(ctx context.Context) (at time.Time, key string, ok bool, err error)
	// ChangedRecords returns up to limit CVE records changed after the
	// cursor (synced_at, cve_id), with their previous state (nil: never
	// seen).
	ChangedRecords(ctx context.Context, at time.Time, key string, limit int) ([]Change, error)
	// Record writes the events, the new states and the cursor in one
	// transaction.
	Record(ctx context.Context, events []Event, states []State, at time.Time, key string) error
	// SyncKEV emits kev_added for each CVE that entered the KEV catalog
	// since the last call (none on the first call, which only records the
	// catalog) and records removals without an event.
	SyncKEV(ctx context.Context) (int, error)
	// SyncEPSS emits epss_crossed for each tracked CVE whose EPSS score
	// rose into a higher band (none on the first call).
	SyncEPSS(ctx context.Context) (int, error)
	// Prune deletes events older than before.
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// Change is one changed record and what was known of it.
type Change struct {
	Prev     *State
	Cur      State
	SyncedAt time.Time
}
